package dev.reachmap.analysis;

import dev.reachmap.entry.ConfigCatalog;
import dev.reachmap.entry.ExtensionPoints;
import dev.reachmap.graph.ReachGraph;
import dev.reachmap.load.ClassPath;
import dev.reachmap.model.*;
import dev.reachmap.util.Json;
import dev.reachmap.util.Log;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Builds the reachability graph.
 *
 * <p>The builder is where every "hidden" call relation is turned into an explicit, labelled
 * edge. Each modelling decision records either an edge with a confidence or an
 * {@link Uncertainty} entry, never nothing: the report's trustworthiness depends on the
 * distinction between "we proved there is no path" and "we could not see this hop".
 */
public final class GraphBuilder {

    private final ClassPath cp;
    private final TypeHierarchy th;
    private final AnalysisOptions opts;
    private final InjectionModel di;
    private final MethodScanner scanner;
    private final ConfigCatalog config;

    private final ReachGraph graph = new ReachGraph();
    private final List<Uncertainty> uncertainties = new ArrayList<>();
    private final Set<String> uncertaintyKeys = new HashSet<>();
    private final Map<MethodId, MethodFacts> factsCache = new HashMap<>();
    private final Map<String, String> staticStringFields = new HashMap<>();

    /** Interfaces implemented by exactly one concrete class on the classpath, or a few. */
    private final Map<String, List<String>> implCache = new HashMap<>();

    public GraphBuilder(ClassPath cp, TypeHierarchy th, AnalysisOptions opts, InjectionModel di,
                        ConfigCatalog config) {
        this.cp = cp;
        this.th = th;
        this.opts = opts;
        this.di = di;
        this.config = config;
        this.scanner = new MethodScanner(staticStringFields);
    }

    public ReachGraph graph() { return graph; }
    public List<Uncertainty> uncertainties() { return uncertainties; }

    // ================================================================== entry

    /**
     * Builds the whole graph.
     *
     * <p>Order matters: callback attachment can introduce new synthetic entries (framework
     * drivers), and those must have their own bytecode closure expanded before the reachability
     * search. The build therefore iterates explore → callbacks until no new synthetic entry
     * appears, which normally means two rounds.
     */
    public void build(List<EntryPoint> entries) {
        collectStaticStringFields();
        registerInstantiatedTypes();

        // 1. Application hints that a type is constructed without a `new` in reachable code.
        registerConfiguredClasses();
        registerServiceProviders();
        registerDiInstantiation();

        // 2. Bytecode closure, then callbacks. Callbacks can add edges to methods whose bodies were
        // never explored (a readObject target, a proxy handler, a configured plugin class), so the
        // loop repeats until neither the entry set nor the graph stops growing.
        int prevEntries = -1;
        int prevNodes = -1;
        int rounds = 0;
        while ((entries.size() != prevEntries || graph.nodes().size() != prevNodes) && rounds++ < 6) {
            prevEntries = entries.size();
            prevNodes = graph.nodes().size();
            explore(entries);
            attachCallbacks(entries);
        }

        Log.info("Graph: %d node(s), %d edge(s), %d uncertain(ties)", graph.nodes().size(), graph.edgeCount(),
                uncertainties.size());
    }

    // ------------------------------------------------------------------ static fields

    private void collectStaticStringFields() {
        for (ClassInfo ci : cp.allClasses()) {
            for (FieldInfo f : ci.fields()) {
                if (f.isStatic() && f.constantValue() instanceof String s) {
                    staticStringFields.put(ci.displayName() + "#" + f.name(), s);
                }
            }
        }
    }

    // ------------------------------------------------------------------ instantiation universe

    private void registerInstantiatedTypes() {
        // Beans are constructed by the container.
        for (String b : di.allBeanClasses()) th.registerInstantiated(b);
        // Classes with a main or an HTTP handler: framework instantiates them.
        for (ClassInfo ci : cp.allClasses()) {
            if (!ci.isApp()) continue;
            if (ci.hasAnnotationSimple("RestController") || ci.hasAnnotationSimple("Controller")
                    || ci.hasAnnotationSimple("Component") || ci.hasAnnotationSimple("Service")
                    || ci.hasAnnotationSimple("Repository") || ci.hasAnnotationSimple("Configuration")
                    || ci.hasAnnotationSimple("WebServlet") || ci.hasAnnotationSimple("Path")) {
                th.registerInstantiated(ci.name());
            }
            for (MethodSig m : ci.methods()) {
                if (m.name().equals("main")) th.registerInstantiated(ci.name());
            }
        }
        // Pre-scan every `new` in application code. Dispatch narrowing for app interfaces uses
        // this set, and the graph is expanded as a worklist, so a type constructed in a method
        // reached late would otherwise be invisible to an interface call expanded earlier — a
        // path could be dropped purely because of traversal order. Application code is small, so
        // scanning it all up front is cheap and removes the ordering hazard.
        preScanAppInstantiations();
    }

    private void preScanAppInstantiations() {
        for (ClassInfo ci : cp.allClasses()) {
            if (!ci.isApp()) continue;
            byte[] bytes = cp.bytesOf(ci.name());
            if (bytes == null) continue;
            org.objectweb.asm.tree.ClassNode cn = new org.objectweb.asm.tree.ClassNode();
            new org.objectweb.asm.ClassReader(bytes).accept(cn,
                    org.objectweb.asm.ClassReader.SKIP_DEBUG | org.objectweb.asm.ClassReader.SKIP_FRAMES);
            for (org.objectweb.asm.tree.MethodNode mn : cn.methods) {
                for (org.objectweb.asm.tree.AbstractInsnNode insn : mn.instructions) {
                    if (insn instanceof org.objectweb.asm.tree.TypeInsnNode ti
                            && ti.getOpcode() == org.objectweb.asm.Opcodes.NEW) {
                        th.registerInstantiated(ti.desc);
                    }
                }
            }
        }
    }

    private void registerConfiguredClasses() {
        for (ConfigCatalog.ConfiguredClass c : config.entries()) {
            if (cp.contains(c.className())) {
                th.registerInstantiated(c.className());
            }
        }
        // @Entity / JPA classes are instantiated by the persistence provider.
        for (ClassInfo ci : cp.allClasses()) {
            if (ci.hasAnnotationSimple("Entity") || ci.hasAnnotationSimple("Document")
                    || ci.hasAnnotationSimple("Embeddable")) {
                th.registerInstantiated(ci.name());
            }
        }
        // Classes with a public no-arg constructor that implement a library extension point are
        // plausibly instantiated by the framework.
        for (ClassInfo ci : cp.allClasses()) {
            if (!ci.isApp()) continue;
            for (ExtensionPoints.Extension e : ExtensionPoints.all()) {
                if (th.isSubtype(ci.name(), e.contract()) && !ci.isInterface() && !ci.isAbstract()) {
                    th.registerInstantiated(ci.name());
                }
            }
        }
    }

    private void registerServiceProviders() {
        for (ClassPath.Root root : cp.roots()) {
            try {
                if (Files.isDirectory(root.path())) {
                    Path services = root.path().resolve("META-INF/services");
                    if (!Files.isDirectory(services)) continue;
                    try (var s = Files.list(services)) {
                        for (Path p : s.toList()) registerServiceFile(p);
                    }
                } else if (root.path().toString().endsWith(".jar")) {
                    try (var jar = new java.util.jar.JarFile(root.path().toFile(), false)) {
                        var en = jar.entries();
                        while (en.hasMoreElements()) {
                            var e = en.nextElement();
                            if (!e.getName().startsWith("META-INF/services/") || e.isDirectory()) continue;
                            String providerType = e.getName().substring("META-INF/services/".length()).trim();
                            try (var in = jar.getInputStream(e)) {
                                String text = new String(in.readAllBytes());
                                registerServiceText(providerType, text);
                            }
                        }
                    }
                }
            } catch (Exception ex) {
                Log.debug("Service provider scan failed for %s: %s", root.path(), ex.getMessage());
            }
        }
    }

    private void registerServiceFile(Path p) throws java.io.IOException {
        String providerType = p.getFileName().toString().trim();
        registerServiceText(providerType, Files.readString(p));
    }

    private void registerServiceText(String providerType, String text) {
        String itf = providerType.replace('.', '/');
        List<String> providers = new ArrayList<>();
        for (String line : text.split("\\R")) {
            String t = line.replaceAll("#.*$", "").trim();
            if (t.isEmpty()) continue;
            String internal = t.replace('.', '/');
            if (cp.contains(internal)) {
                th.registerInstantiated(internal);
                th.registerInstantiated(itf, internal);
                providers.add(internal);
                for (MethodSig m : cp.get(internal).methods()) {
                    if (m.hasCode() && m.isPublic() && !m.isConstructor()) {
                        serviceCallbacks.add(new MethodId(internal, m.name(), m.desc()));
                    }
                }
            }
        }
        serviceRegistrations.put(itf, providers);
    }

    private final Map<String, List<String>> serviceRegistrations = new HashMap<>();
    private final List<MethodId> serviceCallbacks = new ArrayList<>();

    private void registerDiInstantiation() {
        for (InjectionModel.Injection i : di.injections()) {
            for (String c : i.candidates()) th.registerInstantiated(i.declaredType(), c);
        }
    }

    // ------------------------------------------------------------------ closure over bytecode

    private void explore(List<EntryPoint> entries) {
        ArrayDeque<MethodId> work = new ArrayDeque<>();
        Set<MethodId> seen = new HashSet<>();
        for (EntryPoint e : entries) {
            if (seen.add(e.method())) work.add(e.method());
            graph.addNode(e.method(), opts.maxNodes);
            // <init> of an entry class runs before the entry method. A framework-driver entry is
            // synthetic and has no class, so this is guarded.
            if (!e.method().isConstructor() && cp.get(e.method().owner()) != null) {
                MethodId ctor = findNoArgCtor(e.method().owner());
                if (ctor != null && seen.add(ctor)) work.add(ctor);
            }
        }
        // Seed from every node already discovered. Callback attachment (serialization, proxies,
        // config) adds nodes and edges between explore rounds without recomputing them here, so a
        // callback target must be expanded in the next round for its own body to become visible.
        for (MethodId n : new ArrayList<>(graph.nodes())) {
            if (seen.add(n)) work.add(n);
        }
        while (!work.isEmpty()) {
            MethodId m = work.poll();
            List<Edge> edges = expand(m);
            for (Edge ed : edges) {
                graph.addEdge(ed);
                if (seen.add(ed.to())) work.add(ed.to());
            }
        }
        Log.debug("Bytecode closure: %d method(s), %d edge(s)", seen.size(), graph.edgeCount());
    }

    private MethodId findNoArgCtor(String owner) {
        ClassInfo ci = cp.get(owner);
        if (ci == null) return null;
        for (MethodSig m : ci.methods()) if (m.isConstructor() && m.desc().equals("()V") && m.hasCode()) {
            return new MethodId(owner, "<init>", "()V");
        }
        return null;
    }

    private boolean shouldScan(MethodId m) {
        ClassInfo ci = cp.get(m.owner());
        if (ci == null) return false;
        if (ci.isApp()) return true;
        if (!opts.analyzeLibraries) return false;
        // Scanning every library method is necessary for deep vulnerable-library paths, but we
        // skip synthetic/bridge noise and JDK internals unless explicitly asked.
        if (!opts.includeJdk && (m.owner().startsWith("java/") || m.owner().startsWith("javax/")
                || m.owner().startsWith("jdk/") || m.owner().startsWith("sun/"))) return false;
        return true;
    }

    /** All edges leaving one method. */
    private List<Edge> expand(MethodId m) {
        ClassInfo ci = cp.get(m.owner());
        if (ci == null) {
            cp.markMissing(m.owner());
            return List.of();
        }
        MethodSig sig = ci.method(m.name(), m.desc());
        if (sig == null) {
            // Method inherited from a supertype: resolve there.
            String decl = th.declaringClass(m.owner(), m.name(), m.desc());
            if (decl != null && !decl.equals(m.owner())) {
                return List.of(new Edge(m, new MethodId(decl, m.name(), m.desc()),
                        EdgeKind.DIRECT_EXACT, -1, List.of(), "inherited method"));
            }
            return List.of();
        }
        if (!shouldScan(m)) return List.of();

        MethodFacts facts = factsCache.computeIfAbsent(m, this::scanFacts);
        List<Edge> out = new ArrayList<>();

        // static initializer runs when the class is first used
        if (!m.isConstructor() && !"<clinit>".equals(m.name())) {
            addStaticInitEdge(m, ci, out);
        }

        for (MethodFacts.Call call : facts.calls) {
            resolveCall(m, call, out);
        }

        // Constructor edges: `new X()` is exact; also record X.<init> as constructed.
        for (String t : facts.newTypes) {
            th.registerInstantiated(t);
            MethodId ctor = findCtor(t, facts);
            if (ctor != null) out.add(new Edge(m, ctor, EdgeKind.DIRECT_EXACT, -1, List.of(), "new " + t.replace('/', '.')));
        }

        // Reflection where the class was discovered but the method could not be named.
        for (String c : facts.reflectiveClassCandidates) {
            addReflectiveInstantiations(m, c, out);
        }

        for (String reason : facts.unresolvedReason) {
            categorizeUnresolved(m, ci, facts, reason);
        }
        return out;
    }

    private void addStaticInitEdge(MethodId m, ClassInfo ci, List<Edge> out) {
        // The class initializer of the *declaring* class runs before the first static access.
        // We approximate: <clinit> of the owner class is reached when any method of it is called.
        if (ci.hasClinit() && !ci.name().equals(m.owner())) return;
        ClassInfo own = cp.get(m.owner());
        if (own != null && own.hasClinit()) {
            out.add(new Edge(m, new MethodId(own.name(), "<clinit>", "()V"),
                    EdgeKind.STATIC_INIT, -1, List.of(), "class initialization"));
        }
    }

    private MethodId findCtor(String type, MethodFacts facts) {
        ClassInfo ci = cp.get(type);
        if (ci == null) return null;
        // Prefer the constructor whose descriptor matches the number of pushed arguments is not
        // recoverable cheaply; any constructor proves reachability of the class's initialisation.
        for (MethodSig s : ci.methods()) {
            if (s.isConstructor() && s.hasCode() && s.desc().equals("()V")) return new MethodId(type, "<init>", "()V");
        }
        for (MethodSig s : ci.methods()) {
            if (s.isConstructor() && s.hasCode()) return new MethodId(type, "<init>", s.desc());
        }
        return null;
    }

    // ------------------------------------------------------------------ call resolution

    private void resolveCall(MethodId from, MethodFacts.Call call, List<Edge> out) {
        String owner = call.owner;
        ClassInfo ownerCi = cp.requireOrNull(owner);

        if (call.reflective) {
            resolveReflectiveTarget(from, call, out);
            return;
        }

        if (ownerCi == null) {
            cp.markMissing(owner);
            // A call to a class we do not have is a real blind spot, but only if it is app code
            // that could matter; library-internal JDK calls are noise we filter out.
            if (!isJdk(owner)) {
                addUncertainty(Uncertainty.Category.MISSING_CLASS, Uncertainty.Severity.MEDIUM,
                        loc(from, call.line), "Call target " + owner.replace('/', '.')
                                + "." + call.name + " is not on the analyzed classpath", from, UncertaintyCategoryOwner.APP);
            }
            return;
        }

        // Exact edges: static, special, constructor calls.
        if (call.isInvokeStatic() || call.isInvokeSpecial() || call.name.equals("<init>")) {
            MethodId target = new MethodId(owner, call.name, call.desc);
            if (isSyntheticAccess(owner, call.name)) {
                out.add(new Edge(from, target, EdgeKind.SYNTHETIC, call.line, List.of(), "synthetic accessor"));
                return;
            }
            out.add(new Edge(from, target, EdgeKind.DIRECT_EXACT, call.line, List.of(), null));
            addServiceLookupEdge(from, owner, call, out);
            return;
        }

        // Virtual / interface dispatch.
        boolean interfaceCall = call.intf || ownerCi.isInterface();
        String declaredReceiver = call.argType(0);
        boolean narrow = isAppType(owner) && !th.instantiated().isEmpty();
        List<String> targets = th.dispatchTargets(owner, call.name, call.desc, declaredReceiver, narrow);

        if (interfaceCall) {
            // Prefer DI bindings: for a bean-injected interface the container guarantees exactly
            // the injected implementation, which is far more precise than the subtype closure.
            List<String> diTargets = new ArrayList<>();
            for (String c : targets) {
                if (di.beansFor(owner).contains(c)) diTargets.add(c);
            }
            if (!diTargets.isEmpty()) {
                boolean single = diTargets.size() == 1;
                for (String c : diTargets) {
                    MethodId target = new MethodId(c, call.name, call.desc);
                    EdgeKind kind = single ? EdgeKind.DI_BINDING : EdgeKind.DI_AMBIGUOUS;
                    out.add(new Edge(from, target, kind, call.line,
                            single ? List.of() : List.of("interface has " + diTargets.size() + " injected beans"),
                            "bean-injected implementation of " + owner.replace('/', '.')));
                }
                // Keep other implementations only when they can be instantiated outside DI.
                for (String c : targets) {
                    if (diTargets.contains(c)) continue;
                    if (!th.instantiated().contains(c)) continue;
                    out.add(new Edge(from, new MethodId(c, call.name, call.desc),
                            EdgeKind.DISPATCH_NARROWED, call.line,
                            List.of("second instantiation path in addition to DI"), null));
                }
                return;
            }
        }

        if (targets.isEmpty()) {
            // The call exists but nothing on the classpath implements it: either a JDK interface
            // (fine) or a genuinely missing dependency (record it).
            if (!isJdk(owner) && !hasConcreteBody(owner, call.name, call.desc)) {
                addUncertainty(Uncertainty.Category.MISSING_CLASS, Uncertainty.Severity.MEDIUM,
                        loc(from, call.line), "No implementation of " + owner.replace('/', '.') + "."
                                + call.name + " found on the analyzed classpath", from, UncertaintyCategoryOwner.APP);
            }
            return;
        }

        if (targets.size() == 1) {
            String c = targets.get(0);
            boolean exact = c.equals(owner) || isFinalOrPrivate(owner, call.name, call.desc);
            out.add(new Edge(from, new MethodId(c, call.name, call.desc),
                    exact ? EdgeKind.DISPATCH_EXACT : EdgeKind.DISPATCH_NARROWED, call.line,
                    exact ? List.of() : List.of("single concrete implementation on classpath"), null));
            return;
        }

        if (targets.size() > opts.maxDispatchTargets) {
            addUncertainty(Uncertainty.Category.DISPATCH, Uncertainty.Severity.LOW,
                    loc(from, call.line), "Wide dispatch: " + targets.size() + " implementations of "
                            + owner.replace('/', '.') + "." + call.name + "; edges downgraded to WIDE", from,
                    UncertaintyCategoryOwner.LIB);
        }
        for (String c : targets) {
            out.add(new Edge(from, new MethodId(c, call.name, call.desc), EdgeKind.DISPATCH_WIDE, call.line,
                    List.of(targets.size() + " possible implementations"), null));
        }
    }

    private enum UncertaintyCategoryOwner { APP, LIB }

    private void resolveReflectiveTarget(MethodId from, MethodFacts.Call call, List<Edge> out) {
        String owner = call.owner;
        ClassInfo ci = cp.get(owner);
        if (ci == null) {
            addUncertainty(Uncertainty.Category.REFLECTION, Uncertainty.Severity.HIGH, loc(from, call.line),
                    "Reflective target class " + owner.replace('/', '.') + " is not on the classpath", from,
                    UncertaintyCategoryOwner.APP);
            return;
        }
        th.registerInstantiated(owner);
        String name = call.name;

        if (name != null && name.equals("<init>")) {
            for (MethodSig s : ci.methods()) {
                if (s.isConstructor() && s.hasCode()) {
                    out.add(new Edge(from, new MethodId(owner, "<init>", s.desc()),
                            EdgeKind.REFLECT_CONSTANT, call.line, List.of(),
                            call.reflectiveKind + " resolved to a constant class name"));
                    // Constructing a type reflectively runs its initializer and then its ctor; the
                    // ctor is the entry for any further dispatch.
                }
            }
            if (ci.methods().stream().noneMatch(s -> s.isConstructor() && s.hasCode())) {
                addUncertainty(Uncertainty.Category.REFLECTION, Uncertainty.Severity.MEDIUM, loc(from, call.line),
                        "Reflective construction of " + owner.replace('/', '.') + " found no constructor body", from,
                        UncertaintyCategoryOwner.APP);
            }
            return;
        }

        if (name != null) {
            boolean found = false;
            for (MethodSig s : ci.methods()) {
                if (s.name().equals(name) && s.hasCode()) {
                    out.add(new Edge(from, new MethodId(owner, name, s.desc()),
                            EdgeKind.REFLECT_CONSTANT, call.line, List.of(),
                            call.reflectiveKind + " resolved to a constant class/method name"));
                    found = true;
                }
            }
            // Look at supertypes too (inherited reflective target).
            for (String sup : th.supertypes(owner)) {
                ClassInfo sc = cp.get(sup);
                if (sc == null) continue;
                for (MethodSig s : sc.methods()) {
                    if (s.name().equals(name) && s.hasCode() && s.isPublic()) {
                        out.add(new Edge(from, new MethodId(sup, name, s.desc()),
                                EdgeKind.REFLECT_CONSTANT, call.line, List.of(), "inherited reflective target"));
                        found = true;
                    }
                }
            }
            if (!found) {
                addUncertainty(Uncertainty.Category.REFLECTION, Uncertainty.Severity.HIGH, loc(from, call.line),
                        "Reflective call to " + owner.replace('/', '.') + "." + name
                                + " but no matching method body was found", from, UncertaintyCategoryOwner.APP);
            }
            return;
        }

        // Class known, method unknown: every public method body becomes a possible target.
        for (MethodSig s : ci.methods()) {
            if (!s.hasCode() || s.isConstructor() || s.isPrivate()) continue;
            out.add(new Edge(from, new MethodId(owner, s.name(), s.desc()),
                    EdgeKind.REFLECT_CONSTANT, call.line, List.of("method selected dynamically"),
                    "reflective call into a known class; all public entry points considered"));
        }
        addUncertainty(Uncertainty.Category.REFLECTION, Uncertainty.Severity.MEDIUM, loc(from, call.line),
                "Reflective dispatch with a constant class but a dynamic method name in "
                        + owner.replace('/', '.') + "; all public methods assumed reachable", from,
                UncertaintyCategoryOwner.APP);
    }

    private void addReflectiveInstantiations(MethodId from, String owner, List<Edge> out) {
        ClassInfo ci = cp.get(owner);
        if (ci == null) return;
        th.registerInstantiated(owner);
        for (MethodSig s : ci.methods()) {
            if (s.isConstructor() && s.hasCode() && !s.isPrivate()) {
                out.add(new Edge(from, new MethodId(owner, "<init>", s.desc()),
                        EdgeKind.REFLECT_CONFIGURED, -1, List.of(), "reflectively instantiated"));
            }
        }
    }

    private void addServiceLookupEdge(MethodId from, String owner, MethodFacts.Call call, List<Edge> out) {
        // ServiceLoader.load(SomeInterface.class) -> every declared provider of SomeInterface.
        if ("java/util/ServiceLoader".equals(owner) && call.name.equals("load")) {
            ConstValue c = call.constantArg(0);
            for (String itf : c.classNames()) {
                List<String> providers = serviceRegistrations.getOrDefault(itf, List.of());
                for (String p : providers) {
                    MethodId ctor = findNoArgCtor(p);
                    if (ctor != null) {
                        out.add(new Edge(from, ctor, EdgeKind.SERVICE_PROVIDER, call.line, List.of(),
                                "ServiceLoader provider declared in META-INF/services"));
                    }
                }
                if (providers.isEmpty()) {
                    addUncertainty(Uncertainty.Category.SERVICE_LOADER, Uncertainty.Severity.MEDIUM,
                            loc(from, call.line), "ServiceLoader.load(" + itf.replace('/', '.')
                                    + ") found no META-INF/services declaration on the classpath", from,
                            UncertaintyCategoryOwner.APP);
                }
            }
        }
    }

    // ------------------------------------------------------------------ callbacks

    private void attachCallbacks(List<EntryPoint> entries) {
        SearchResultSnapshot reach = reachableSnapshot(entries);

        // Serialization callbacks: every reachable method that actually reads an object stream is
        // a site where the JVM may invoke readObject on an unknown, attacker-chosen class. The
        // callbacks are attached from those sites, so the proof reads "this endpoint deserializes,
        // therefore this callback can run" rather than "this callback is an entry point".
        for (MethodId m : reach.reached) {
            MethodFacts f = factsCache.get(m);
            if (f != null && f.readsSerializedStream) attachSerializationCallbacks(m);
        }

        // Framework callbacks for extension-point implementations discovered from DI/config.
        attachFrameworkCallbacks(entries, reach);

        // Dynamic proxies: Proxy.newProxyInstance(Iface.class, ...) makes every interface method
        // a possible dispatch into the handler's invoke().
        attachProxyCallbacks(reach);

        // ServiceLoader providers: the framework calls every declared provider.
        attachServiceCallbacks(reach);

        // Config-driven classes: their constructors + plugin callbacks are entered by config.
        attachConfiguredClasses(reach);
    }

    private record SearchResultSnapshot(Set<MethodId> reached) {}

    private SearchResultSnapshot reachableSnapshot(List<EntryPoint> entries) {
        List<MethodId> roots = new ArrayList<>();
        for (EntryPoint e : entries) roots.add(e.method());
        return new SearchResultSnapshot(graph.reachFrom(roots, opts.maxDepth, opts.maxNodes).reachedNodes());
    }

    /**
     * Attaches Java-serialization callbacks.
     *
     * <p>The attacker chooses the class name inside the stream, so the set of classes that may be
     * deserialized is <em>every Serializable class on the classpath</em>, not just classes the
     * call graph reaches — that is the whole point of a gadget chain. Attaching only to already
     * reached classes would miss exactly the callback that carries the attack. The over-approximation
     * is unsafe for "unreachable" claims, so it always records a HIGH uncertainty explaining that
     * the deserialized set cannot be enumerated.
     *
     * <p>Library classes are included only if they define a callback body; JDK classes are skipped
     * since their callbacks are framework-internal and not the vulnerable app's code.
     */
    private void attachSerializationCallbacks(MethodId site) {
        int count = 0;
        Set<MethodId> attached = new HashSet<>();
        for (ClassInfo ci : cp.allClasses()) {
            if (ci.isInterface() || ci.isAbstract()) continue;
            if (ci.name().startsWith("java/") || ci.name().startsWith("javax/")
                    || ci.name().startsWith("jdk/") || ci.name().startsWith("sun/")) continue;
            if (!th.isSubtype(ci.name(), "java/io/Serializable")) continue;
            // A library class is only a target if it is reachable at all (constructed or called),
            // otherwise every Serializable type in every jar becomes a false path. Application
            // classes are all in play because deserialization can name any of them.
            boolean inPlay = ci.isApp() || graph.nodes().stream().anyMatch(n -> n.owner().equals(ci.name()));
            if (!inPlay) continue;
            boolean externalizable = th.isSubtype(ci.name(), "java/io/Externalizable");
            Set<String> callbacks = new HashSet<>(List.of("readObject", "readResolve", "readObjectNoData"));
            if (externalizable) callbacks.add("readExternal");
            for (MethodSig s : ci.methods()) {
                if (!callbacks.contains(s.name()) || !s.hasCode()) continue;
                MethodId target = new MethodId(ci.name(), s.name(), s.desc());
                if (!attached.add(target)) continue;
                graph.addEdge(new Edge(site, target, EdgeKind.FRAMEWORK_CALLBACK, -1,
                        List.of("deserialized instance of a Serializable class reachable from an app "
                                + "deserialization site"),
                        "java serialization callback"));
                count++;
            }
        }
        if (count > 0) {
            addUncertainty(Uncertainty.Category.SERIALIZATION, Uncertainty.Severity.HIGH, site.display(),
                    "One or more ObjectInputStream.readObject() call sites exist; " + count
                            + " serialization callback(s) on reachable classes were attached. The set of "
                            + "classes actually deserialized cannot be determined statically.",
                    site, UncertaintyCategoryOwner.APP);
        }
    }

    /**
     * Framework-invoked callbacks (servlet listeners, Spring lifecycle beans, Jackson
     * deserializers, snakeyaml constructors).
     *
     * <p>The caller is the container, not any bytecode method, so the honest model is a synthetic
     * entry node standing for "the framework invokes X". Anchoring these callbacks on an arbitrary
     * reachable method would fabricate a path that does not exist and, worse, could displace the
     * real proof path in the report.
     *
     * <p>log4j2's {@code @Plugin} dispatch is *not* modelled here: the plugin interface is invoked
     * by ordinary bytecode (e.g. {@code Interpolator.lookup} calls {@code StrLookup.lookup}), so
     * normal interface dispatch already reaches the implementations.
     */
    private void attachFrameworkCallbacks(List<EntryPoint> entries, SearchResultSnapshot reach) {
        Map<ExtensionPoints.Extension, List<MethodId>> byExtension = new LinkedHashMap<>();
        for (MethodId m : reach.reached()) {
            ClassInfo ci = cp.get(m.owner());
            if (ci == null || ci.isInterface() || ci.isAbstract()) continue;
            // Application code only. A library class that happens to implement a library contract
            // (snakeyaml's own ConstructYamlObject implements Construct, for instance) is reached
            // through ordinary bytecode if it is used at all; declaring every such class a
            // framework callback entry would fabricate paths from nowhere to library internals.
            if (!isAppType(ci.name())) continue;
            for (ExtensionPoints.Extension ext : ExtensionPoints.all()) {
                if (ext.discovery() != ExtensionPoints.Discovery.SUBTYPE) continue;
                if (ext.framework().startsWith("log4j2")) continue;
                if (!th.isSubtype(ci.name(), ext.contract())) continue;
                // Only implementations that really get constructed can be called back.
                boolean constructed = th.instantiated().contains(ci.name())
                        || di.allBeanClasses().contains(ci.name())
                        || reach.reached().contains(new MethodId(ci.name(), "<init>", "()V"));
                if (!constructed) continue;
                for (String cb : ext.callbacks()) {
                    for (MethodSig s : ci.methods()) {
                        if (!s.name().equals(cb) || !s.hasCode()) continue;
                        byExtension.computeIfAbsent(ext, k -> new ArrayList<>())
                                .add(new MethodId(ci.name(), s.name(), s.desc()));
                    }
                }
            }
        }
        for (Map.Entry<ExtensionPoints.Extension, List<MethodId>> e : byExtension.entrySet()) {
            ExtensionPoints.Extension ext = e.getKey();
            MethodId driver = new MethodId("dev/reachmap/framework/" + sanitize(ext.framework()),
                    ext.callbacks().get(0), "()V");
            graph.addNode(driver, opts.maxNodes);
            entries.add(new EntryPoint(driver, EntryKind.FRAMEWORK_CALLBACK, null, null,
                    ext.framework() + " invokes " + ext.contract().replace('/', '.') + " implementations",
                    driver.displayClass()));
            for (MethodId target : new LinkedHashSet<>(e.getValue())) {
                graph.addEdge(new Edge(driver, target, EdgeKind.FRAMEWORK_CALLBACK, -1,
                        List.of("framework " + ext.framework()
                                + " invokes this callback on every registered implementation"),
                        "extension point " + ext.contract().replace('/', '.')));
            }
        }
    }

    private static String sanitize(String s) {
        return s.replaceAll("[^A-Za-z0-9]", "_");
    }

    /**
     * Dynamic proxy callbacks.
     *
     * <p>The anchor is the bytecode that actually creates a proxy ({@code Proxy.newProxyInstance}
     * or a cglib enhancer), not an arbitrary reachable method: "the proxy is created here, so its
     * handler runs when this code invokes the proxied interface" is a claim a reviewer can check.
     * When proxies exist but no creation site is in the graph, no edge is created at all rather
     * than inventing one.
     */
    private void attachProxyCallbacks(SearchResultSnapshot reach) {
        List<MethodId> handlers = new ArrayList<>();
        for (ClassInfo ci : cp.allClasses()) {
            if (ci.isInterface() || ci.isAbstract()) continue;
            if (!th.isSubtype(ci.name(), "java/lang/reflect/InvocationHandler")) continue;
            if (!th.instantiated().contains(ci.name())) continue;
            for (MethodSig s : ci.methods()) {
                if (s.name().equals("invoke") && s.hasCode()) handlers.add(new MethodId(ci.name(), s.name(), s.desc()));
            }
        }
        if (handlers.isEmpty()) return;

        // Locate the reachable proxy creation sites.
        List<MethodId> creationSites = new ArrayList<>();
        for (MethodId m : reach.reached()) {
            MethodFacts f = factsCache.get(m);
            if (f == null) continue;
            for (MethodFacts.Call c : f.calls) {
                boolean jdkProxy = "java/lang/reflect/Proxy".equals(c.owner) && c.name.equals("newProxyInstance");
                boolean cglib = c.owner.startsWith("net/sf/cglib") || c.owner.startsWith("org/springframework/cglib");
                if (jdkProxy || cglib) { creationSites.add(m); break; }
            }
        }
        if (creationSites.isEmpty()) return;

        for (MethodId site : creationSites) {
            for (MethodId h : handlers) {
                graph.addEdge(new Edge(site, h, EdgeKind.CALLBACK_OPEN, -1,
                        List.of("dynamic proxy handler; the proxied interface and call site are not statically determined"),
                        "InvocationHandler.invoke"));
            }
            addUncertainty(Uncertainty.Category.DYNAMIC_PROXY, Uncertainty.Severity.HIGH, site.display(),
                    "A dynamic proxy is created here; dispatch into " + handlers.size()
                            + " reachable InvocationHandler(s) is modelled as open callbacks. Which handler "
                            + "receives which interface method is not statically determined.",
                    site, UncertaintyCategoryOwner.APP);
        }
    }

    private void attachServiceCallbacks(SearchResultSnapshot reach) {
        for (Map.Entry<String, List<String>> e : serviceRegistrations.entrySet()) {
            // If any reachable method calls ServiceLoader.load(Iface) or uses iface as a bean,
            // the providers' methods are entered by the framework.
            boolean relevant = false;
            MethodId anchor = null;
            for (MethodId m : reach.reached()) {
                MethodFacts f = factsCache.get(m);
                if (f == null) continue;
                for (MethodFacts.Call c : f.calls) {
                    if ("java/util/ServiceLoader".equals(c.owner)) {
                        for (String itf : c.constantArg(0).classNames()) {
                            if (itf.equals(e.getKey())) { relevant = true; anchor = m; }
                        }
                    }
                }
            }
            if (!relevant) continue;
            for (String p : e.getValue()) {
                ClassInfo ci = cp.get(p);
                if (ci == null) continue;
                for (MethodSig s : ci.methods()) {
                    if (!s.hasCode() || s.isConstructor() || s.isPrivate()) continue;
                    graph.addEdge(new Edge(anchor, new MethodId(p, s.name(), s.desc()),
                            EdgeKind.SERVICE_PROVIDER, -1,
                            List.of("service provider registered in META-INF/services"), null));
                }
            }
        }
    }

    /**
     * Configuration-selected implementations.
     *
     * <p>A class named in {@code plugin.properties} or {@code log4j2.xml} gets instantiated by code
     * that reads the file. The anchor is therefore the reachable <em>reflective load site</em>
     * ({@code Class.forName} / {@code newInstance} / {@code loadClass}) when one exists, and a
     * synthetic "config loader" entry only when the file is consumed by a framework whose loader
     * is not on the classpath. Either way the edge carries the file and key that justify it.
     */
    private void attachConfiguredClasses(SearchResultSnapshot reach) {
        List<ConfigCatalog.ConfiguredClass> hits = new ArrayList<>();
        for (ConfigCatalog.ConfiguredClass c : config.entries()) {
            if (!cp.contains(c.className())) continue;
            String key = c.key() == null ? "" : c.key().toLowerCase(Locale.ROOT);
            boolean classKey = key.contains("class") || key.contains("type") || key.contains("impl")
                    || key.contains("handler") || key.contains("factory") || key.contains("strategy");
            boolean ext = false;
            for (ExtensionPoints.Extension e : ExtensionPoints.all()) {
                if (th.isSubtype(c.className(), e.contract())) { ext = true; break; }
            }
            if (!classKey && !ext) continue;
            hits.add(c);
        }
        if (hits.isEmpty()) return;

        // Reachable reflective load sites, in deterministic order.
        List<MethodId> loadSites = new ArrayList<>();
        for (MethodId m : reach.reached()) {
            MethodFacts f = factsCache.get(m);
            if (f == null) continue;
            for (MethodFacts.Call c : f.calls) {
                boolean forName = "java/lang/Class".equals(c.owner) && c.name.equals("forName");
                boolean loadClass = c.name.equals("loadClass");
                boolean newInstance = "newInstance".equals(c.name) || "getDeclaredConstructor".equals(c.name);
                if (forName || loadClass || newInstance) { loadSites.add(m); break; }
            }
        }
        MethodId synthetic = null;
        if (loadSites.isEmpty()) {
            synthetic = new MethodId("dev/reachmap/config", "load", "(Ljava/util/Properties;)V");
            graph.addNode(synthetic, opts.maxNodes);
        }

        for (ConfigCatalog.ConfiguredClass c : hits) {
            ClassInfo ci = cp.get(c.className());
            if (ci == null) continue;
            List<MethodId> constructed = new ArrayList<>();
            for (MethodSig s : ci.methods()) {
                if (s.isConstructor() && s.hasCode()) constructed.add(new MethodId(ci.name(), s.name(), s.desc()));
            }
            List<MethodId> callbacks = new ArrayList<>();
            for (ExtensionPoints.Extension ext : ExtensionPoints.all()) {
                if (!th.isSubtype(ci.name(), ext.contract())) continue;
                for (String cb : ext.callbacks()) {
                    for (MethodSig s : ci.methods()) {
                        if (s.name().equals(cb) && s.hasCode()) callbacks.add(new MethodId(ci.name(), s.name(), s.desc()));
                    }
                }
            }
            List<MethodId> anchors = loadSites.isEmpty() ? List.of(synthetic) : loadSites;
            for (MethodId a : anchors) {
                for (MethodId t : constructed) {
                    graph.addEdge(new Edge(a, t, EdgeKind.CONFIG_DRIVEN, -1,
                            List.of("class name appears in " + c.file() + " (key " + c.key() + ")"),
                            "configuration-selected implementation"));
                }
                for (MethodId t : callbacks) {
                    if (constructed.contains(t)) continue;
                    graph.addEdge(new Edge(a, t, EdgeKind.CONFIG_DRIVEN, -1,
                            List.of("invoked by the framework because the class is named in " + c.file()),
                            "configured extension implementation"));
                }
            }
        }

        MethodId location = loadSites.isEmpty() ? synthetic : loadSites.get(0);
        addUncertainty(Uncertainty.Category.CONFIGURATION, Uncertainty.Severity.MEDIUM,
                location.display(), hits.size() + " configured class(es) were treated as "
                        + "framework-selected implementations because a configuration file names them",
                location, UncertaintyCategoryOwner.APP);
    }

    // ------------------------------------------------------------------ helpers

    private MethodFacts scanFacts(MethodId m) {
        byte[] bytes = cp.bytesOf(m.owner());
        if (bytes == null) return new MethodFacts();
        return scanner.scan(bytes, m.name(), m.desc());
    }

    /**
     * Turns an unresolved dynamic dispatch into a ledger entry.
     *
     * <p>Library internals are only recorded at all when they are genuinely reflective; a dataflow
     * failure inside a dependency method would otherwise flood the ledger with thousands of
     * entries that cannot hide a path (the method is already reached). Application code is always
     * recorded, because that is where an unseen hop can turn UNREACHABLE into a live path.
     */
    private void categorizeUnresolved(MethodId m, ClassInfo ci, MethodFacts facts, String reason) {
        boolean app = isAppType(m.owner());
        Uncertainty.Category cat = Uncertainty.Category.REFLECTION;
        Uncertainty.Severity sev = Uncertainty.Severity.HIGH;
        if (reason.contains("ObjectInputStream")) {
            cat = Uncertainty.Category.SERIALIZATION;
        } else if (reason.contains("dataflow")) {
            cat = Uncertainty.Category.DATAFLOW;
            sev = Uncertainty.Severity.MEDIUM;
        }
        if (!app && cat == Uncertainty.Category.DATAFLOW) return;
        addUncertainty(cat, sev, m.display(), reason, m,
                app ? UncertaintyCategoryOwner.APP : UncertaintyCategoryOwner.LIB);
    }

    private static final Pattern JDK = Pattern.compile("^(java|javax|jdk|sun|com/sun|org/w3c|org/xml|org/ietf)/.*");

    private static boolean isJdk(String internal) { return JDK.matcher(internal).matches(); }

    private boolean isAppType(String internal) {
        ClassInfo ci = cp.get(internal);
        return ci != null && ci.isApp();
    }

    private boolean isSyntheticAccess(String owner, String name) {
        return name.startsWith("access$") || name.startsWith("lambda$");
    }

    private boolean isFinalOrPrivate(String owner, String name, String desc) {
        ClassInfo ci = cp.get(owner);
        if (ci == null) return false;
        MethodSig m = ci.method(name, desc);
        return m != null && m.isFinal();
    }

    private boolean hasConcreteBody(String owner, String name, String desc) {
        return th.hasConcreteBody(owner, name, desc);
    }

    private String loc(MethodId m, int line) {
        return m.display() + (line > 0 ? ":" + line : "");
    }

    private void addUncertainty(Uncertainty.Category cat, Uncertainty.Severity sev, String location,
                                String description, MethodId method, UncertaintyCategoryOwner ownerKind) {
        String key = cat + "|" + location + "|" + description;
        if (!uncertaintyKeys.add(key)) return;
        boolean app = ownerKind == UncertaintyCategoryOwner.APP && method != null
                && (cp.isApp(method.owner()) || opts.isAppPackage(method.owner()));
        String artifact = null;
        if (method != null) {
            ClassInfo ci = cp.get(method.owner());
            if (ci != null) artifact = ci.artifact();
        }
        uncertainties.add(new Uncertainty(cat, sev, location, description,
                method == null ? null : method.owner() + "#" + method.name() + method.desc(), artifact, app));
    }
}
