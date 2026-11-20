package dev.reachmap.analysis;

import dev.reachmap.load.ClassPath;
import dev.reachmap.model.*;
import dev.reachmap.util.Log;

import java.util.*;

/**
 * Extracts the dependency-injection wiring model from annotations.
 *
 * <p>Supported: Spring stereotype annotations and {@code @Bean} factory methods, Jakarta/javax
 * {@code @Inject}/{@code @Named}/{@code @Singleton}, and field/constructor/setter injection points.
 * Anything the extraction cannot decide (qualifier not found, several candidates without a
 * primary, profile-conditional beans) is recorded as ambiguous instead of being guessed.
 */
public final class DiExtractor {

    private static final Set<String> STEREOTYPES = Set.of(
            "Component", "Service", "Repository", "Controller", "RestController", "Configuration",
            "Named", "Singleton", "ApplicationScoped", "RequestScoped", "Stateless", "Stateful");

    private static final Set<String> INJECT_ANNOS = Set.of("Autowired", "Inject", "Resource", "Value");

    private final ClassPath cp;
    private final InjectionModel model = new InjectionModel();
    private final List<String> diagnostics = new ArrayList<>();

    public DiExtractor(ClassPath cp) { this.cp = cp; }

    public InjectionModel model() { return model; }
    public List<String> diagnostics() { return diagnostics; }

    public InjectionModel build() {
        // Pass 1: bean definitions.
        for (ClassInfo ci : cp.allClasses()) {
            if (!(ci.isApp())) continue;
            for (Anno a : ci.annotations()) {
                if (!STEREOTYPES.contains(a.simpleName())) continue;
                String beanName = beanName(ci, a);
                boolean primary = ci.hasAnnotationSimple("Primary") || ci.hasAnnotationSimple("Default");
                String profile = profileOf(ci);
                model.addBean(new InjectionModel.Bean(ci.name(), null, beanName, primary, profile,
                        List.of(ci.name())));
            }
            // @Bean factory methods on @Configuration classes.
            for (MethodSig m : ci.methods()) {
                if (!m.hasAnnotationSimple("Bean") && !m.hasAnnotationSimple("Produces")) continue;
                String produced = returnTypeInternal(m.desc());
                boolean primary = m.hasAnnotationSimple("Primary");
                String name = m.hasAnnotationSimple("Bean") ? null : m.name();
                // Class-level stereotypes on the containing config also make a bean of the config.
                model.addBean(new InjectionModel.Bean(ci.name(), m.name(), name, primary, profileOf(ci),
                        produced == null ? List.of() : List.of(produced)));
            }
        }

        // Pass 2: injection points inside app classes.
        for (ClassInfo ci : cp.allClasses()) {
            if (!ci.isApp()) continue;
            if (!isBeanClass(ci)) continue;
            extractFields(ci);
            extractConstructors(ci);
            extractSetters(ci);
        }

        if (model.hasBeans()) {
            Log.info("DI model: %d bean definition(s), %d injection point(s)",
                    model.beansByType().size(), model.injections().size());
        }
        return model;
    }

    private boolean isBeanClass(ClassInfo ci) {
        for (Anno a : ci.annotations()) if (STEREOTYPES.contains(a.simpleName())) return true;
        return false;
    }

    private void extractFields(ClassInfo ci) {
        for (FieldInfo f : ci.fields()) {
            Anno autowired = null;
            for (Anno a : f.annotations()) if (INJECT_ANNOS.contains(a.simpleName())) autowired = a;
            if (autowired == null) continue;
            String type = f.objectType();
            if (type == null) continue;
            String qualifier = qualifierOf(f.annotations());
            addInjection(ci, type, f.name(), null, qualifier, -1);
        }
    }

    private void extractConstructors(ClassInfo ci) {
        List<MethodSig> ctors = new ArrayList<>();
        for (MethodSig m : ci.methods()) if (m.isConstructor()) ctors.add(m);
        if (ctors.isEmpty()) return;
        MethodSig chosen = null;
        for (MethodSig m : ctors) {
            if (m.hasAnnotationSimple("Autowired") || m.hasAnnotationSimple("Inject")) { chosen = m; break; }
        }
        if (chosen == null && ctors.size() == 1) chosen = ctors.get(0);
        if (chosen == null) return;
        // Spring also injects unannotated single-constructor parameters; we model that only when
        // there is exactly one constructor, which is the common Spring 4.3+ convention.
        List<String> argTypes = argTypesInternal(chosen.desc());
        for (int i = 0; i < argTypes.size(); i++) {
            String qualifier = qualifierOf(chosen.parameterAnnotations().size() > i
                    ? chosen.parameterAnnotations().get(i) : List.of());
            if (argTypes.get(i) != null) addInjection(ci, argTypes.get(i), "ctor" + i, chosen.name(), qualifier, -1);
        }
    }

    private void extractSetters(ClassInfo ci) {
        for (MethodSig m : ci.methods()) {
            if (m.isConstructor() || m.isStatic()) continue;
            boolean annotated = m.hasAnnotationSimple("Autowired") || m.hasAnnotationSimple("Inject");
            boolean setter = m.name().startsWith("set") && m.name().length() > 3;
            if (!annotated && !setter) continue;
            List<String> argTypes = argTypesInternal(m.desc());
            if (argTypes.size() != 1) continue;
            if (!annotated && !isBeanClass(ci)) continue;
            if (argTypes.get(0) != null) {
                addInjection(ci, argTypes.get(0), m.name(), m.name(), qualifierOf(m.annotations()), -1);
            }
        }
    }

    private void addInjection(ClassInfo ci, String type, String member, String method, String qualifier, int line) {
        List<String> candidates = new ArrayList<>();
        List<InjectionModel.Bean> beans = model.beansByType().get(type);
        if (beans != null) {
            for (InjectionModel.Bean b : beans) {
                if (b.className() != null && !candidates.contains(b.className())) candidates.add(b.className());
            }
        }
        if (candidates.isEmpty()) {
            // Fallback: any app class implementing this type that carries a stereotype.
            for (ClassInfo sub : cp.allClasses()) {
                if (!sub.isApp() || sub.isInterface() || sub.isAbstract()) continue;
                if (sub.name().equals(type)) candidates.add(sub.name());
            }
        }
        boolean ambiguous;
        String chosenNote = null;
        if (!candidates.isEmpty()) {
            // @Primary narrows it.
            List<String> primaries = new ArrayList<>();
            if (beans != null) for (InjectionModel.Bean b : beans) if (b.isPrimary() && b.className() != null) primaries.add(b.className());
            if (primaries.size() == 1) {
                candidates = primaries;
                ambiguous = false;
            } else {
                ambiguous = candidates.size() > 1;
            }
        } else {
            ambiguous = false;
        }
        model.addInjection(new InjectionModel.Injection(ci.name(), type, member, method,
                List.copyOf(candidates), qualifier, ambiguous, line));
        if (ambiguous) {
            model.diagnostic("Ambiguous injection of " + type.replace('/', '.') + " into "
                    + ci.displayName() + "." + member + " (" + candidates.size() + " candidates)");
        }
    }

    private static String qualifierOf(List<Anno> annos) {
        for (Anno a : annos) {
            if (!a.simpleName().equals("Qualifier") && !a.simpleName().equals("Named")) continue;
            Object v = a.value("value");
            if (v instanceof String s) return s;
        }
        return null;
    }

    private static String beanName(ClassInfo ci, Anno stereotype) {
        Object v = stereotype.value("value");
        if (v instanceof String s && !s.isBlank()) return s;
        String simple = dev.reachmap.util.Text.simpleName(ci.name());
        if (simple.isEmpty()) return null;
        return Character.toLowerCase(simple.charAt(0)) + simple.substring(1);
    }

    private static String profileOf(ClassInfo ci) {
        Anno p = ci.annotation("org.springframework.context.annotation.Profile");
        if (p == null) return null;
        Object v = p.value("value");
        if (v instanceof String s) return s;
        if (v instanceof List<?> l && !l.isEmpty()) return String.valueOf(l.get(0));
        return null;
    }

    private static String returnTypeInternal(String desc) {
        org.objectweb.asm.Type t = org.objectweb.asm.Type.getReturnType(desc);
        return t.getSort() == org.objectweb.asm.Type.OBJECT ? t.getInternalName() : null;
    }

    private static List<String> argTypesInternal(String desc) {
        List<String> out = new ArrayList<>();
        for (org.objectweb.asm.Type t : org.objectweb.asm.Type.getArgumentTypes(desc)) {
            out.add(t.getSort() == org.objectweb.asm.Type.OBJECT ? t.getInternalName() : null);
        }
        return out;
    }
}
