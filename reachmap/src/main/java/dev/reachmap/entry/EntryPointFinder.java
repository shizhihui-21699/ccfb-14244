package dev.reachmap.entry;

import dev.reachmap.analysis.AnalysisOptions;
import dev.reachmap.load.ClassPath;
import dev.reachmap.model.*;
import dev.reachmap.util.Log;

import java.util.*;

/**
 * Discovers entry points: the places where control enters the application from outside.
 *
 * <p>The entry set defines what "reachable" means. We restrict entries to application code by
 * default, because a library class is not itself an entry point just for existing; the exception
 * is explicitly configured entries and framework lifecycle callbacks on app classes (a
 * {@code ServletContextListener} in app code really is entered by the container).
 */
public final class EntryPointFinder {

    /** A method whose parameter (by index) carries attacker-controlled data. */
    public record TaintedParam(int index, String name) {}

    private final ClassPath cp;
    private final AnalysisOptions opts;
    private final InjectionModelRef injection;
    private final List<EntryPoint> entries = new ArrayList<>();
    private final List<String> diagnostics = new ArrayList<>();

    /** Receives the DI model after it is built, since entries and wiring share annotations. */
    public record InjectionModelRef(dev.reachmap.analysis.InjectionModel model) {}

    public EntryPointFinder(ClassPath cp, AnalysisOptions opts, InjectionModelRef injection) {
        this.cp = cp;
        this.opts = opts;
        this.injection = injection;
    }

    public List<EntryPoint> entries() { return entries; }
    public List<String> diagnostics() { return diagnostics; }

    public void discover() {
        for (ClassInfo ci : cp.allClasses()) {
            boolean app = ci.isApp() || opts.isAppPackage(ci.name());
            boolean configured = opts.entryClasses.contains(ci.displayName()) || isCustomEntryClass(ci);
            if (!app && !configured) continue;
            scanClass(ci, app);
        }
        for (String spec : opts.entryMethods) {
            MethodId id = parseMethodSpec(spec);
            if (id != null) {
                entries.add(new EntryPoint(id, EntryKind.CUSTOM, null, null,
                        "declared in analysis config", id.displayClass()));
            } else {
                diagnostics.add("Unparseable entry method: " + spec);
            }
        }
        // Startup entries: bean @PostConstruct / InitializingBean in app code.
        if (opts.startupAsEntry) {
            for (ClassInfo ci : cp.allClasses()) {
                if (!isApp(ci)) continue;
                for (MethodSig m : ci.methods()) {
                    if (m.hasAnnotation("jakarta.annotation.PostConstruct")
                            || m.hasAnnotation("javax.annotation.PostConstruct")
                            || m.hasAnnotation("org.springframework.beans.factory.annotation.PostConstruct")) {
                        entries.add(new EntryPoint(mid(ci, m), EntryKind.SPRING_COMPONENT_INIT, null, null,
                                "@PostConstruct executed during bean initialization", ci.displayName()));
                    }
                }
            }
            // Framework-instantiated classes: the container runs the constructor before the handler
            // method. Modelling the constructor as a startup entry is what makes field initializers
            // (a `new Handler()` stored in a field, a `Proxy.newProxyInstance` call) reachable —
            // otherwise a proxy or handler created in the constructor is invisible.
            for (ClassInfo ci : cp.allClasses()) {
                if (!isApp(ci)) continue;
                if (!frameworkInstantiates(ci)) continue;
                MethodSig ctor = noArgCtor(ci);
                if (ctor == null) continue;
                entries.add(new EntryPoint(mid(ci, ctor), EntryKind.SPRING_COMPONENT_INIT, null, null,
                        "instance constructed by the framework before its handlers run", ci.displayName()));
            }
        }
        dedupe();
        Log.info("Discovered %d entry point(s): %s", entries.size(), summary());
    }

    private boolean isApp(ClassInfo ci) {
        return ci.isApp() || opts.isAppPackage(ci.name());
    }

    private static boolean frameworkInstantiates(ClassInfo ci) {
        return ci.hasAnnotationSimple("RestController") || ci.hasAnnotationSimple("Controller")
                || ci.hasAnnotationSimple("Component") || ci.hasAnnotationSimple("Service")
                || ci.hasAnnotationSimple("Repository") || ci.hasAnnotationSimple("Configuration")
                || ci.hasAnnotationSimple("WebServlet") || ci.hasAnnotationSimple("WebFilter")
                || ci.hasAnnotationSimple("WebListener") || ci.hasAnnotationSimple("Path");
    }

    private static MethodSig noArgCtor(ClassInfo ci) {
        for (MethodSig m : ci.methods()) {
            if (m.isConstructor() && m.desc().equals("()V") && m.hasCode()) return m;
        }
        return null;
    }

    private boolean isCustomEntryClass(ClassInfo ci) {
        for (String e : opts.entryClasses) {
            if (ci.displayName().equals(e) || ci.displayName().startsWith(e + ".")) return true;
        }
        return false;
    }

    private String summary() {
        Map<EntryKind, Integer> counts = new EnumMap<>(EntryKind.class);
        for (EntryPoint e : entries) counts.merge(e.kind(), 1, Integer::sum);
        StringBuilder sb = new StringBuilder();
        counts.forEach((k, v) -> sb.append(k.name()).append('=').append(v).append(' '));
        return sb.toString().trim();
    }

    private void dedupe() {
        Map<String, EntryPoint> seen = new LinkedHashMap<>();
        for (EntryPoint e : entries) {
            String key = e.method().owner() + "#" + e.method().name() + e.method().desc() + "@" + e.kind();
            seen.putIfAbsent(key, e);
        }
        entries.clear();
        entries.addAll(seen.values());
    }

    private void scanClass(ClassInfo ci, boolean app) {
        List<String> classRoutes = classLevelRoutes(ci);
        for (MethodSig m : ci.methods()) {
            if (m.isSynthetic() && !m.name().equals("main")) continue;
            MethodId id = mid(ci, m);

            // ---- Spring MVC / Spring Boot annotations
            String route = null;
            String httpMethods = null;
            EntryKind kind = null;

            Anno mapping = firstOf(m, "RequestMapping", "GetMapping", "PostMapping", "PutMapping",
                    "DeleteMapping", "PatchMapping");
            if (mapping != null) {
                route = joinRoute(classRoutes, pathOf(mapping));
                httpMethods = httpMethodsOf(mapping);
                kind = EntryKind.SPRING_CONTROLLER;
                Anno sq = ann(m, "ResponseBody");
                if (mapping.simpleName().equals("RequestMapping") && sq != null) {
                    // @Controller + @ResponseBody == REST; still an HTTP endpoint either way.
                }
                if (ci.hasAnnotationSimple("RestController")) kind = EntryKind.SPRING_CONTROLLER;
            }

            // ---- JAX-RS
            if (kind == null) {
                Anno jax = firstOf(m, "GET", "POST", "PUT", "DELETE", "PATCH", "Path");
                if (jax != null && (classHasAnnotation(ci, "Path") || ci.hasAnnotationSimple("ApplicationPath"))) {
                    kind = EntryKind.JAXRS_RESOURCE;
                    route = joinRoute(classRoutes, jax.stringValue("value"));
                    httpMethods = jax.simpleName().equals("Path") ? null : jax.simpleName();
                }
            }

            // ---- Servlet
            if (kind == null && (m.name().equals("doGet") || m.name().equals("doPost")
                    || m.name().equals("doPut") || m.name().equals("doDelete")
                    || m.name().equals("service") || m.name().equals("doFilter"))) {
                if (isSubtypeOf(ci.name(), "javax/servlet/Servlet") || isSubtypeOf(ci.name(), "jakarta/servlet/Servlet")
                        || isSubtypeOf(ci.name(), "javax/servlet/Filter") || isSubtypeOf(ci.name(), "jakarta/servlet/Filter")) {
                    kind = EntryKind.SERVLET;
                    route = servletMapping(ci);
                    httpMethods = m.name().startsWith("do") ? m.name().substring(2).toUpperCase(Locale.ROOT) : "ANY";
                }
            }

            if (kind != null) {
                EntryPoint ep = new EntryPoint(id, kind, route, httpMethods,
                        "annotated handler", ci.displayName());
                markFrameworkTaintedParams(ep, m);
                entries.add(ep);
            }

            // ---- main()
            if (m.name().equals("main") && m.isStatic()
                    && (m.desc().equals("([Ljava/lang/String;)V"))) {
                EntryKind k = ci.hasAnnotationSimple("SpringBootApplication")
                        ? EntryKind.SPRING_BOOT_MAIN : EntryKind.MAIN_METHOD;
                EntryPoint ep = new EntryPoint(id, k, null, null, "process entry", ci.displayName());
                entries.add(ep);
                if (opts.startupAsEntry) {
                    // Spring Boot main boots the context: all beans get constructed and their
                    // lifecycle callbacks run. Model that as a startup edge from main.
                }
            }

            // ---- scheduled / message listeners
            if (opts.scheduledAsEntry) {
                if (m.hasAnnotationSimple("Scheduled") || m.hasAnnotationSimple("EventListener")) {
                    entries.add(new EntryPoint(id, EntryKind.SPRING_SCHEDULED, null, null,
                            "scheduled/event listener", ci.displayName()));
                }
                if (m.hasAnnotationSimple("JmsListener") || m.hasAnnotationSimple("RabbitListener")
                        || m.hasAnnotationSimple("KafkaListener") || m.hasAnnotationSimple("StreamListener")) {
                    entries.add(new EntryPoint(id, EntryKind.SPRING_MESSAGE_LISTENER, null, null,
                            "message listener", ci.displayName()));
                }
            }

            // ---- @Bean wiring: the factory method itself runs at startup
            if (opts.startupAsEntry && m.hasAnnotationSimple("Bean")) {
                entries.add(new EntryPoint(id, EntryKind.SPRING_CONFIGURATION, null, null,
                        "Spring @Bean factory method runs at startup", ci.displayName()));
            }
        }

        // ---- Extension point callbacks declared on app classes (filters, listeners, ...)
        scanExtensionCallbacks(ci);

        // ---- reflection-only libraries: class-level plugin annotations
        scanPluginAnnotations(ci);
    }

    /**
     * Extension interfaces whose callbacks are entered by the container rather than by request
     * handling: servlet listeners, Spring lifecycle beans, Jackson (de)serializers.
     *
     * <p>Serialization callbacks are deliberately <em>not</em> listed as entries. A
     * {@code readObject} method is invoked by deserialization at some call site, and the graph
     * builder attaches it there; declaring it an entry point would make every {@code Serializable}
     * class look reachable and would hide the real question ("does an entry point actually
     * deserialize an attacker stream?").
     */
    private void scanExtensionCallbacks(ClassInfo ci) {
        for (ExtensionPoints.Extension ext : ExtensionPoints.all()) {
            if (!isSubtypeOf(ci.name(), ext.contract())) continue;
            if (ext.framework().equals("java-serialization") || ext.framework().equals("externalizable")) continue;
            if (ext.discovery() != ExtensionPoints.Discovery.SUBTYPE) continue;
            boolean declaredInApp = ci.isApp() || cp.isApp(ci.name());
            if (!declaredInApp && !opts.entryClasses.contains(ci.displayName())) continue;
            if (ci.isInterface() || ci.isAbstract()) continue;
            for (MethodSig m : ci.methods()) {
                if (!ext.callbacks().contains(m.name()) || !m.hasCode()) continue;
                entries.add(new EntryPoint(mid(ci, m), EntryKind.FRAMEWORK_CALLBACK, null, null,
                        "framework callback via " + ext.framework() + " (" + ext.contract() + ")", ci.displayName()));
            }
        }
    }

    private void scanPluginAnnotations(ClassInfo ci) {
        // log4j @Plugin classes: registered through the plugin system, used by Interpolator.
        if (ci.hasAnnotationSimple("Plugin")) {
            Anno plugin = null;
            for (Anno a : ci.annotations()) if (a.simpleName().equals("Plugin")) plugin = a;
            String category = plugin == null ? null : plugin.stringValue("category");
            if (pluginsInAppOnly()) return;
            for (ExtensionPoints.Extension ext : ExtensionPoints.all()) {
                if (ext.discovery() != ExtensionPoints.Discovery.ANNOTATION) continue;
                if (!isSubtypeOf(ci.name(), ext.contract())) continue;
                for (MethodSig m : ci.methods()) {
                    if (ext.callbacks().contains(m.name())) {
                        entries.add(new EntryPoint(mid(ci, m), EntryKind.CUSTOM, null, null,
                                "plugin callback " + category + " discovered by " + ext.framework(), ci.displayName()));
                    }
                }
            }
        }
    }

    private boolean pluginsInAppOnly() { return false; }

    private EntryPoint findExisting(MethodId id, EntryKind kind) {
        for (EntryPoint e : entries) if (e.method().equals(id)) return e;
        return null;
    }

    private void markFrameworkTaintedParams(EntryPoint ep, MethodSig m) {
        List<String> params = new ArrayList<>();
        List<Integer> indexes = new ArrayList<>();
        for (int i = 0; i < m.parameterAnnotations().size(); i++) {
            for (Anno a : m.parameterAnnotations().get(i)) {
                String s = a.simpleName();
                if (s.equals("RequestParam") || s.equals("PathVariable") || s.equals("RequestBody")
                        || s.equals("RequestHeader") || s.equals("ModelAttribute") || s.equals("CookieValue")
                        || s.equals("QueryParam") || s.equals("FormParam") || s.equals("PathParam")) {
                    params.add(m.parameterNames().size() > i && m.parameterNames().get(i) != null
                            ? m.parameterNames().get(i) : "arg" + i);
                    indexes.add(i);
                    break;
                }
            }
        }
        // Spring's HttpServletRequest / MultipartFile parameters are attacker-controlled too.
        int argIndex = 0;
        for (String t : argTypes(m.desc())) {
            if (t != null && (t.startsWith("javax/servlet/http/") || t.startsWith("jakarta/servlet/http/")
                    || t.contains("MultipartFile"))) {
                if (!indexes.contains(argIndex)) { params.add("arg" + argIndex); indexes.add(argIndex); }
            }
            argIndex++;
        }
        // A servlet/filter entry receives request+response directly; the request (index 0) is input.
        if (indexes.isEmpty() && ep.kind() == EntryKind.SERVLET) {
            List<String> types = argTypes(m.desc());
            for (int i = 0; i < types.size(); i++) {
                if (types.get(i) != null && types.get(i).contains("HttpServletRequest")) {
                    params.add("arg" + i); indexes.add(i);
                }
            }
        }
        ep.withTaintedParams(params);
        ep.withTaintedParamIndexes(indexes);
    }

    // ------------------------------------------------------------------ helpers

    private static MethodId mid(ClassInfo ci, MethodSig m) {
        return new MethodId(ci.name(), m.name(), m.desc());
    }

    private Anno ann(MethodSig m, String simple) {
        for (Anno a : m.annotations()) if (a.simpleName().equals(simple)) return a;
        return null;
    }

    private boolean classHasAnnotation(ClassInfo ci, String simple) {
        for (Anno a : ci.annotations()) if (a.simpleName().equals(simple)) return true;
        return false;
    }

    private Anno firstOf(MethodSig m, String... simples) {
        for (String s : simples) {
            Anno a = ann(m, s);
            if (a != null) return a;
        }
        return null;
    }

    private List<String> classLevelRoutes(ClassInfo ci) {
        List<String> routes = new ArrayList<>();
        for (Anno a : ci.annotations()) {
            if (a.simpleName().equals("RequestMapping") || a.simpleName().equals("Path")) {
                Object v = a.value("value");
                if (v instanceof String s) routes.add(s);
                else if (v instanceof List<?> l) for (Object o : l) if (o instanceof String s) routes.add(s);
            }
        }
        if (routes.isEmpty()) return null;
        return routes;
    }

    private String joinRoute(List<String> classRoutes, String methodPath) {
        String base = classRoutes == null || classRoutes.isEmpty() ? "" : classRoutes.get(0);
        if (methodPath == null) methodPath = "";
        String joined = ("/" + base + "/" + methodPath).replaceAll("/{2,}", "/");
        return joined;
    }

    private String pathOf(Anno mapping) {
        Object v = mapping.value("value");
        if (v == null) v = mapping.value("path");
        if (v instanceof String s) return s;
        if (v instanceof List<?> l && !l.isEmpty()) return String.valueOf(l.get(0));
        return null;
    }

    private String httpMethodsOf(Anno mapping) {
        String s = mapping.simpleName();
        if (s.endsWith("Mapping") && !s.equals("RequestMapping")) return s.substring(0, s.length() - 7).toUpperCase(Locale.ROOT);
        Object v = mapping.value("method");
        if (v instanceof List<?> l && !l.isEmpty()) {
            List<String> ms = new ArrayList<>();
            for (Object o : l) ms.add(String.valueOf(o));
            return String.join(",", ms);
        }
        if (v instanceof String s2) return s2;
        return "ANY";
    }

    private String servletMapping(ClassInfo ci) {
        Anno w = ci.annotation("javax.servlet.annotation.WebServlet");
        if (w == null) w = ci.annotation("jakarta.servlet.annotation.WebServlet");
        if (w == null) return null;
        Object v = w.value("value");
        if (v == null) v = w.value("urlPatterns");
        if (v instanceof String s) return s;
        if (v instanceof List<?> l && !l.isEmpty()) return String.join(",", l.stream().map(String::valueOf).toList());
        return null;
    }

    private boolean isSubtypeOf(String sub, String sup) {
        if (sub == null || sup == null) return false;
        if (sub.equals(sup)) return true;
        Deque<String> work = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        work.add(sub);
        while (!work.isEmpty()) {
            String cur = work.poll();
            if (!seen.add(cur)) continue;
            ClassInfo ci = cp.get(cur);
            if (ci == null) continue;
            if (sup.equals(ci.superName()) || ci.interfaces().contains(sup)) return true;
            if (ci.superName() != null) work.add(ci.superName());
            work.addAll(ci.interfaces());
        }
        return false;
    }

    private List<String> argTypes(String desc) {
        List<String> out = new ArrayList<>();
        org.objectweb.asm.Type[] t = org.objectweb.asm.Type.getArgumentTypes(desc);
        for (org.objectweb.asm.Type a : t) {
            out.add(a.getSort() == org.objectweb.asm.Type.OBJECT ? a.getInternalName() : a.getClassName());
        }
        return out;
    }

    private MethodId parseMethodSpec(String spec) {
        // Accepted: com.acme.Foo#bar(java.lang.String) | com.acme.Foo#bar | com.acme.Foo#main
        int hash = spec.indexOf('#');
        if (hash <= 0) return null;
        String cls = spec.substring(0, hash).trim().replace('.', '/');
        String rest = spec.substring(hash + 1).trim();
        String name = rest;
        String desc = null;
        int paren = rest.indexOf('(');
        if (paren >= 0) {
            name = rest.substring(0, paren);
            String args = rest.substring(paren + 1, rest.endsWith(")") ? rest.length() - 1 : rest.length());
            if (args.isBlank()) desc = "()V";
        }
        ClassInfo ci = cp.get(cls);
        if (ci == null) return null;
        for (MethodSig m : ci.methods()) {
            if (m.name().equals(name) && (desc == null || desc.equals(m.desc()))) {
                return new MethodId(cls, m.name(), m.desc());
            }
        }
        return null;
    }
}
