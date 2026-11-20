package dev.reachmap.analysis;

import java.util.*;

/**
 * Knowledge about how application objects are wired, gathered from annotation style dependency
 * injection (Spring, CDI) and explicit configuration.
 *
 * <p>This is what turns {@code invokeinterface PaymentGateway.pay} from a call to "every class
 * implementing the interface on the classpath" into a call to the one bean that is actually
 * injected at that field. It is also where ambiguity is recorded: when several beans could be
 * injected, the report says so instead of silently picking one.
 */
public final class InjectionModel {

    /** One injection point: a field, constructor parameter or setter inside a class. */
    public record Injection(String targetClass, String declaredType, String memberName,
                            String intoMethod, List<String> candidates, String qualifier,
                            boolean ambiguous, int line) {}

    /** A bean definition: an annotated class or a @Bean/@Provides factory method. */
    public record Bean(String className, String factoryMethod, String name, boolean isPrimary,
                       String profile, List<String> produces) {}

    private final Map<String, List<Bean>> beansByType = new HashMap<>();
    private final Map<String, Bean> beansByName = new HashMap<>();
    private final List<Injection> injections = new ArrayList<>();
    private final Map<String, List<String>> injectionByType = new HashMap<>();
    private final List<String> diagnostics = new ArrayList<>();

    public void addBean(Bean b) {
        if (b.className() != null) beansByType.computeIfAbsent(b.className(), k -> new ArrayList<>()).add(b);
        for (String p : b.produces()) beansByType.computeIfAbsent(p, k -> new ArrayList<>()).add(b);
        if (b.name() != null) beansByName.putIfAbsent(b.name(), b);
    }

    public void addInjection(Injection i) {
        injections.add(i);
        injectionByType.computeIfAbsent(i.declaredType(), k -> new ArrayList<>()).add(i.targetClass());
    }

    public void diagnostic(String msg) { diagnostics.add(msg); }

    public List<Injection> injections() { return injections; }
    public List<String> diagnostics() { return diagnostics; }

    public Map<String, List<Bean>> beansByType() { return beansByType; }

    /** Concrete bean classes that can satisfy an injection of {@code declaredType}. */
    public List<String> beansFor(String declaredType) {
        List<Bean> beans = beansByType.get(declaredType);
        if (beans == null) return List.of();
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (Bean b : beans) if (b.className() != null) out.add(b.className());
        return List.copyOf(out);
    }

    /** All injection points whose declared type is {@code declaredType} (for callback discovery). */
    public List<Injection> injectionsOfType(String declaredType) {
        List<Injection> out = new ArrayList<>();
        for (Injection i : injections) if (i.declaredType().equals(declaredType)) out.add(i);
        return out;
    }

    /** Field/parameter/method names in which this type is injected; used for callbacks. */
    public List<String> injectedMemberNames(String declaredType) {
        List<String> out = new ArrayList<>();
        for (Injection i : injections) if (i.declaredType().equals(declaredType)) out.add(i.memberName());
        return out;
    }

    public boolean hasBeans() { return !beansByType.isEmpty(); }

    public List<String> allBeanClasses() {
        LinkedHashSet<String> s = new LinkedHashSet<>();
        for (Bean b : beansByName.values()) if (b.className() != null) s.add(b.className());
        for (List<Bean> l : beansByType.values()) for (Bean b : l) if (b.className() != null) s.add(b.className());
        return List.copyOf(s);
    }
}
