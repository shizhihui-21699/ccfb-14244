package dev.reachmap.analysis;

import dev.reachmap.load.ClassPath;
import dev.reachmap.model.ClassInfo;
import dev.reachmap.model.MethodId;
import dev.reachmap.model.MethodSig;

import java.util.*;

/**
 * Class hierarchy queries: supertypes, subtype closure, and virtual dispatch resolution.
 *
 * <p>Dispatch resolution is the precision-critical piece. Given {@code invokeinterface Foo.m()}
 * there may be dozens of implementations on a large classpath; dispatching to all of them is what
 * makes naive reachability tools useless. We therefore intersect the subtype closure with the set
 * of types that are actually <em>instantiable in the reachable program</em> (from {@code new},
 * framework bean definitions, ServiceLoader declarations, and reflective construction), and only
 * fall back to the full closure when that set is unknown.
 */
public final class TypeHierarchy {

    private final ClassPath cp;
    private final Map<String, List<String>> supertypesCache = new HashMap<>();
    private final Map<String, List<String>> allSubtypesCache = new HashMap<>();
    private final Map<String, List<String>> directSubtypesCache = new HashMap<>();
    private final Map<String, Set<String>> instantiatedByStaticType = new HashMap<>();
    private final Set<String> instantiated = new HashSet<>();
    private final Set<String> openWorldTypes = new HashSet<>();

    public TypeHierarchy(ClassPath cp) { this.cp = cp; }

    public ClassPath classPath() { return cp; }

    // ------------------------------------------------------------------ hierarchy

    /** All supertypes (classes and interfaces) in breadth-first order, excluding the type itself. */
    public List<String> supertypes(String internalName) {
        return supertypesCache.computeIfAbsent(internalName, n -> {
            LinkedHashSet<String> out = new LinkedHashSet<>();
            Deque<String> work = new ArrayDeque<>();
            work.add(n);
            while (!work.isEmpty()) {
                String cur = work.poll();
                ClassInfo ci = cp.requireOrNull(cur);
                if (ci == null) continue;
                if (ci.superName() != null && out.add(ci.superName())) work.add(ci.superName());
                for (String itf : ci.interfaces()) if (out.add(itf)) work.add(itf);
            }
            return List.copyOf(out);
        });
    }

    public boolean isSubtype(String sub, String sup) {
        if (sub == null || sup == null) return false;
        if (sub.equals(sup)) return true;
        if ("java/lang/Object".equals(sup)) return true;
        return supertypes(sub).contains(sup);
    }

    /** Direct subtypes (classes extending / implementing) limited to the indexed classpath. */
    public List<String> directSubtypes(String internalName) {
        return directSubtypesCache.computeIfAbsent(internalName, n -> {
            List<String> out = new ArrayList<>();
            for (ClassInfo ci : cp.allClasses()) {
                if (n.equals(ci.superName()) || ci.interfaces().contains(n)) out.add(ci.name());
            }
            return List.copyOf(out);
        });
    }

    /** Full subtype closure including the type itself. */
    public List<String> allSubtypes(String internalName) {
        return allSubtypesCache.computeIfAbsent(internalName, n -> {
            LinkedHashSet<String> seen = new LinkedHashSet<>();
            Deque<String> work = new ArrayDeque<>();
            seen.add(n);
            work.add(n);
            while (!work.isEmpty()) {
                for (String s : directSubtypes(work.poll())) {
                    if (seen.add(s)) work.add(s);
                }
            }
            return List.copyOf(seen);
        });
    }

    // ------------------------------------------------------------------ instantiation universe

    public void registerInstantiated(String internalName) {
        if (internalName != null) instantiated.add(internalName);
    }

    /** Records that a value of static type {@code declaredType} may hold {@code concrete}. */
    public void registerInstantiated(String declaredType, String concrete) {
        instantiated.add(concrete);
        instantiatedByStaticType.computeIfAbsent(declaredType, k -> new HashSet<>()).add(concrete);
    }

    public Set<String> instantiated() { return instantiated; }

    /** Types whose runtime set is not statically enumerable (proxies, reflection, config). */
    public void markOpenWorld(String internalName) {
        if (internalName != null) openWorldTypes.add(internalName);
    }

    public boolean isOpenWorld(String internalName) {
        return openWorldTypes.contains(internalName);
    }

    public Set<String> openWorldTypes() { return openWorldTypes; }

    // ------------------------------------------------------------------ method resolution

    /** Resolves {@code name+desc} starting at {@code internalName} and walking supertypes. */
    public MethodSig resolveMethod(String internalName, String name, String desc) {
        ClassInfo ci = cp.requireOrNull(internalName);
        if (ci == null) return null;
        MethodSig m = ci.method(name, desc);
        if (m != null) return m;
        if (ci.superName() != null) {
            MethodSig sup = resolveMethod(ci.superName(), name, desc);
            if (sup != null) return sup;
        }
        for (String itf : ci.interfaces()) {
            MethodSig im = resolveMethod(itf, name, desc);
            if (im != null) return im;
        }
        return null;
    }

    /** True if the class (or a supertype) has a concrete body for this method. */
    public boolean hasConcreteBody(String internalName, String name, String desc) {
        MethodSig m = resolveMethod(internalName, name, desc);
        return m != null && m.hasCode();
    }

    /** Returns the class in the hierarchy that actually declares the concrete method. */
    public String declaringClass(String internalName, String name, String desc) {
        String cur = internalName;
        Set<String> seen = new HashSet<>();
        while (cur != null && seen.add(cur)) {
            ClassInfo ci = cp.get(cur);
            if (ci == null) return null;
            MethodSig m = ci.method(name, desc);
            if (m != null) return m.hasCode() ? cur : null;
            cur = ci.superName();
        }
        return null;
    }

    /**
     * Concrete targets of a virtual or interface call.
     *
     * <p>The instantiated-universe narrowing is only applied to <em>application</em> interfaces,
     * where we can enumerate every implementation, every constructor call and every bean. Library
     * interfaces must keep their full subtype closure: a library constructs its own
     * implementations through reflection, plugin registries and service files, so narrowing them
     * to what visible bytecode instantiates silently drops real paths — the exact false-negative
     * class this tool exists to avoid.
     *
     * @param owner          static owner type from the bytecode
     * @param name           method name
     * @param desc           method descriptor
     * @param declaredType   additional type restriction from a receiver (may be null)
     * @param narrowToInstantiated whether the owner is app code whose implementations we know
     */
    public List<String> dispatchTargets(String owner, String name, String desc,
                                        String declaredType, boolean narrowToInstantiated) {
        LinkedHashSet<String> targets = new LinkedHashSet<>();
        List<String> candidates = allSubtypes(owner);

        if (narrowToInstantiated && !instantiated.isEmpty()) {
            for (String c : candidates) if (instantiated.contains(c)) targets.add(c);
        }
        if (targets.isEmpty()) targets.addAll(candidates);

        // Receiver-type narrowing: if the value flowing into the call has a declared type that is a
        // proper subtype of the static owner, only that subtree can receive the call. This is the
        // difference between "any StrLookup implementation" and "the JndiLookup this factory
        // returned". Applied only when it leaves at least one concrete target, so a slightly wrong
        // local type never erases a real edge.
        if (declaredType != null && !declaredType.isEmpty()
                && !declaredType.equals(owner) && isSubtype(declaredType, owner)) {
            LinkedHashSet<String> narrowed = new LinkedHashSet<>();
            for (String c : targets) if (isSubtype(c, declaredType)) narrowed.add(c);
            if (!narrowed.isEmpty()) targets = narrowed;
        }
        if (declaredType != null) {
            Set<String> restricted = instantiatedByStaticType.get(declaredType);
            if (restricted != null && !restricted.isEmpty()) {
                LinkedHashSet<String> r = new LinkedHashSet<>();
                for (String c : targets) if (restricted.contains(c) || isSubtype(c, declaredType)) r.add(c);
                if (!r.isEmpty()) targets = r;
            }
        }

        // Keep only classes that actually provide a concrete body reachable for this call.
        List<String> resolved = new ArrayList<>();
        for (String c : targets) {
            ClassInfo ci = cp.get(c);
            if (ci == null) continue;
            if (ci.isInterface() || ci.isAbstract()) continue;
            if (hasConcreteBody(c, name, desc)) resolved.add(c);
        }
        if (resolved.isEmpty()) {
            // The static owner itself may carry the body (e.g. a non-abstract class, or a
            // library class whose subtypes are not on the classpath).
            if (hasConcreteBody(owner, name, desc) && !cp.get(owner).isAbstract()) resolved.add(owner);
        }
        return resolved;
    }

    /** True if the type is concrete (non-interface, non-abstract) and has a no-arg-ish body. */
    public boolean isConcrete(String internalName) {
        ClassInfo ci = cp.get(internalName);
        return ci != null && !ci.isInterface() && !ci.isAbstract();
    }
}
