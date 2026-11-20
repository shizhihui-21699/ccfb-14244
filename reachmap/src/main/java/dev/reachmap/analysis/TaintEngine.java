package dev.reachmap.analysis;

import dev.reachmap.graph.ReachGraph;
import dev.reachmap.load.ClassPath;
import dev.reachmap.model.ClassInfo;
import dev.reachmap.model.MethodId;
import dev.reachmap.model.MethodSig;
import dev.reachmap.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.*;

import java.util.*;

/**
 * Interprocedural taint tracking, used to separate "reachable with attacker input" from
 * "structurally reachable but no attacker input".
 *
 * <p>The question answered is narrow and concrete: <em>can a value derived from one of the
 * entry point's attacker-controlled parameters be an argument or receiver of a call to the
 * vulnerable method?</em>
 *
 * <h2>Model</h2>
 * Taint is a set of parameter indices per method (context-insensitive). A small per-method
 * dataflow computes, for a given tainted-parameter set, which call arguments become tainted and
 * whether the return value is tainted:
 * <ul>
 *   <li>a tainted argument to a call taints the corresponding callee parameter;</li>
 *   <li>a call whose arguments include a tainted value produces a tainted result when it returns
 *       a reference type or is a constructor (this is how message/event/container objects carry
 *       input forward — the case that matters for logging and template sinks);</li>
 *   <li>reading a reference field of a tainted object yields a tainted value; a constructor that
 *       stores a tainted argument into a field makes that field tainted (field-insensitive,
 *       keyed by owner+name).</li>
 * </ul>
 *
 * <h2>Why this is conservative in the right direction</h2>
 * A false positive here would mean labelling a non-exploitable finding as input-reachable, which
 * is precisely the noise this tool exists to remove. So taint only flows through provable
 * value/argument relations; when a hop cannot be justified, the result is UNKNOWN, not YES. The
 * engine is never used to claim something is <em>unreachable</em>.
 */
public final class TaintEngine {

    public enum Result {
        /** A tainted value demonstrably arrives at the sink call. */
        YES,
        /** The path exists but taint provably stops before the sink (e.g. constant message). */
        NO,
        /** Not enough information to decide. */
        UNKNOWN,
        /** The entry point takes no attacker-controlled parameter. */
        NOT_APPLICABLE
    }

    private final ClassPath cp;
    private final ReachGraph graph;
    private final Map<MethodId, MethodTaint> cache = new HashMap<>();
    private final Map<String, BitSet> fieldTaint = new HashMap<>();
    private final Map<String, List<String>> implIndex = new HashMap<>();   // interface -> concrete impls

    public TaintEngine(ClassPath cp, ReachGraph graph) {
        this.cp = cp;
        this.graph = graph;
    }

    /**
     * Reports whether tainted input enters any method owned by {@code artifactPackages}.
     *
     * <p>This is the "did the vulnerable library ever receive attacker data?" question. It exists
     * because data-flow-through-parsers cannot be tracked soundly: {@code Yaml.load(tainted
     * Reader)} feeds a parser whose output is not value-identical to its input, and a serializer
     * that reads attacker bytes is equally opaque. For a deserialization/parsing vulnerability,
     * however, entering the parser <em>is</em> the exposure. So the rule is: if attacker input is
     * passed as an argument (or receiver) to a call inside the vulnerable artifact, the sink is
     * input-reachable.
     *
     * <p>Precision comes from the caller side: a constant log message passes no taint into log4j,
     * while a message built from a request parameter does. That is exactly the distinction that
     * separates an exploitable Log4Shell endpoint from a benign one.
     */
    public Result entersArtifact(MethodId entry, List<Integer> attackerParams, java.util.function.Predicate<String> inArtifact) {
        if (attackerParams == null || attackerParams.isEmpty()) return Result.NOT_APPLICABLE;

        Map<MethodId, BitSet> taintedParams = new HashMap<>();
        ArrayDeque<MethodId> work = new ArrayDeque<>();
        BitSet start = new BitSet();
        for (int p : attackerParams) start.set(p);
        taintedParams.put(entry, start);
        work.add(entry);

        Set<MethodId> visited = new HashSet<>();
        boolean unknown = false;
        int steps = 0;
        while (!work.isEmpty() && steps++ < 30_000) {
            MethodId m = work.poll();
            BitSet params = taintedParams.get(m);
            if (params == null || params.isEmpty()) continue;

            MethodTaint mt = local(m, params);
            if (mt == null) { unknown = true; continue; }

            if (mt.isEmpty()) {
                ClassInfo ici = cp.get(m.owner());
                boolean abstractOwner = ici != null && (ici.isInterface() || ici.isAbstract());
                if (abstractOwner) {
                    for (MethodId impl : implMethods(m)) {
                        BitSet target = taintedParams.computeIfAbsent(impl, k -> new BitSet());
                        boolean added = target.isEmpty();
                        target.or(params);
                        if (added || visited.add(impl)) work.add(impl);
                    }
                }
                continue;
            }

            for (CallTaint ct : mt.calls) {
                if (ct.taintedArg && inArtifact.test(ct.owner)) return Result.YES;
            }

            // Marshalling approximation: if this method took tainted input, wrapped it in some
            // object via a constructor (`new StringReader(amount)`, `new ByteArrayInputStream(bytes)`),
            // and then calls into the vulnerable artifact, treat the input as having entered the
            // artifact. The wrapper object itself cannot be tainted by a bytecode dataflow, because
            // `<init>` returns void and ASM discards the operation result; so this local rule
            // recovers the common "parse this string/bytes" pattern. It is scoped to one method and
            // is only used for this exposure question, never to prove structural reachability.
            boolean marshalled = false;
            for (CallTaint ct : mt.calls) {
                if (ct.taintedArg && "<init>".equals(ct.name)) { marshalled = true; break; }
            }
            if (marshalled) {
                for (CallTaint ct : mt.calls) {
                    if (inArtifact.test(ct.owner) && !"<init>".equals(ct.name)) return Result.YES;
                }
            }
            for (CallTaint ct : mt.calls) {
                if (!ct.taintedArg || ct.taintedParamPositions.isEmpty()) continue;
                for (MethodId callee : calleeTargets(ct)) {
                    BitSet target = taintedParams.computeIfAbsent(callee, k -> new BitSet());
                    int before = target.cardinality();
                    target.or(ct.taintedParamPositions);
                    if (target.cardinality() != before || visited.add(callee)) work.add(callee);
                }
            }
        }
        if (unknown) return Result.UNKNOWN;
        return Result.NO;
    }

    /**
     * Taint from {@code entry}'s attacker parameters, searching the whole reachable graph.
     *
     * <p>The search is deliberately independent of which proof path the report printed: the
     * shortest structural path may legitimately be a static initializer that carries no input,
     * while a longer path through a log call does. Reachability and input-reachability are
     * therefore two separate questions with two separate searches.
     *
     * <p>Bounded by step count; on exhaustion the result is UNKNOWN rather than NO, so a budget
     * cut can never be misreported as "input cannot reach this".
     */
    /**
     * Interprocedural taint result plus the method chain that carried it.
     *
     * <p>The chain matters for the report: when a structural proof path is a static initializer
     * chain that carries no input, the taint chain is the evidence that a <em>different</em>,
     * input-carrying path also exists. The analyzer uses it to choose the path worth printing.
     */
    public record Trace(Result result, List<MethodId> chain) {
        public static Trace of(Result r) { return new Trace(r, List.of()); }
        public boolean yes() { return result == Result.YES; }
    }

    /**
     * Runs taint towards a sink and returns both the verdict and the chain of methods the taint
     * travelled along, so the report can print the input-carrying path as evidence.
     */
    public Trace traceSink(MethodId entry, List<Integer> attackerParams, String sinkOwner, String sinkName) {
        if (attackerParams == null || attackerParams.isEmpty()) return Trace.of(Result.NOT_APPLICABLE);

        Map<MethodId, BitSet> taintedParams = new HashMap<>();
        ArrayDeque<MethodId> work = new ArrayDeque<>();
        Map<MethodId, MethodId> parent = new HashMap<>();
        BitSet start = new BitSet();
        for (int p : attackerParams) start.set(p);
        taintedParams.put(entry, start);
        work.add(entry);

        Set<MethodId> visited = new HashSet<>();
        boolean unknown = false;
        int steps = 0;
        while (!work.isEmpty() && steps++ < 30_000) {
            MethodId m = work.poll();
            BitSet params = taintedParams.get(m);
            if (params == null || params.isEmpty()) continue;

            // Being at the sink method with tainted parameters is enough: the call may have been
            // dispatched through an interface (StrLookup.lookup -> JndiLookup.lookup), so the
            // syntactic call-site owner is not the sink's class.
            if (m.owner().equals(sinkOwner)
                    && (sinkName == null || sinkName.isEmpty() || m.name().equals(sinkName))) {
                List<MethodId> chain = chainTo(m, parent, entry);
                return new Trace(Result.YES, chain);
            }

            MethodTaint mt = local(m, params);
            if (mt == null) {
                unknown = true;
                if (Log.isDebug()) Log.debug("taint: %s params=%s -> NO BODY", m.display(), params);
                continue;
            }

            if (mt.isEmpty()) {
                ClassInfo ici = cp.get(m.owner());
                boolean abstractOwner = ici != null && (ici.isInterface() || ici.isAbstract());
                if (abstractOwner) {
                    for (MethodId impl : implMethods(m)) {
                        BitSet target = taintedParams.computeIfAbsent(impl, k -> new BitSet());
                        boolean added = target.isEmpty();
                        target.or(params);
                        if (added || visited.add(impl)) { work.add(impl); parent.putIfAbsent(impl, m); }
                    }
                }
                continue;
            }

            if (Log.isDebug()) {
                Log.debug("taint: %s params=%s calls=%d", m.display(), params, mt.calls.size());
                for (CallTaint ct : mt.calls) {
                    if (ct.taintedArg) Log.debug("   -> %s.%s taintedArgs=%s", ct.owner, ct.name, ct.taintedParamPositions);
                }
            }
            for (CallTaint ct : mt.calls) {
                boolean hitsSink = ct.owner.equals(sinkOwner)
                        && (sinkName == null || sinkName.isEmpty() || ct.name.equals(sinkName))
                        && ct.taintedArg;
                if (hitsSink) {
                    List<MethodId> chain = chainTo(m, parent, entry);
                    MethodId sink = new MethodId(ct.owner, ct.name, ct.desc);
                    chain.add(sink);
                    return new Trace(Result.YES, chain);
                }
            }

            for (CallTaint ct : mt.calls) {
                if (!ct.taintedArg || ct.taintedParamPositions.isEmpty()) continue;
                for (MethodId callee : calleeTargets(ct)) {
                    BitSet target = taintedParams.computeIfAbsent(callee, k -> new BitSet());
                    int before = target.cardinality();
                    target.or(ct.taintedParamPositions);
                    if (target.cardinality() != before || visited.add(callee)) {
                        work.add(callee);
                        parent.putIfAbsent(callee, m);
                    }
                }
            }
        }
        if (unknown) return Trace.of(Result.UNKNOWN);
        return Trace.of(Result.NO);
    }

    /** Walks parent links back to the entry, producing entry..m in order. */
    private static List<MethodId> chainTo(MethodId m, Map<MethodId, MethodId> parent, MethodId entry) {
        LinkedList<MethodId> chain = new LinkedList<>();
        MethodId cur = m;
        int guard = 0;
        while (cur != null && guard++ < 10_000) {
            chain.addFirst(cur);
            if (cur.equals(entry)) break;
            cur = parent.get(cur);
        }
        return chain;
    }

    // ------------------------------------------------------------------ per-method summary

    private static final class CallTaint {
        final String owner, name, desc;
        final boolean taintedArg;
        final BitSet taintedParamPositions;   // callee parameter indices receiving taint
        CallTaint(String owner, String name, String desc, boolean taintedArg, BitSet positions) {
            this.owner = owner; this.name = name; this.desc = desc;
            this.taintedArg = taintedArg; this.taintedParamPositions = positions;
        }
    }

    private static final class MethodTaint {
        final List<CallTaint> calls = new ArrayList<>();
        boolean returnsTainted;
        boolean isEmpty() { return calls.isEmpty(); }
    }

    /**
     * Concrete implementations a call may land in.
     *
     * <p>The graph already resolved interface and virtual calls to concrete classes; taint must
     * follow the same targets, or a path through an interface (which is how almost every library
     * callback is expressed) would carry no taint at all. When the owner is a class with a body,
     * the call is treated as exact.
     */
    private List<MethodId> calleeTargets(CallTaint ct) {
        List<MethodId> out = new ArrayList<>();
        MethodId self = new MethodId(ct.owner, ct.name, ct.desc);
        ClassInfo ci = cp.get(ct.owner);
        boolean abstractOwner = ci != null && (ci.isInterface() || ci.isAbstract());
        if (!abstractOwner) { out.add(self); return out; }

        for (String impl : concreteImplementations(ct.owner)) {
            MethodId id = new MethodId(impl, ct.name, ct.desc);
            if (graph.nodes().contains(id)) out.add(id);
        }
        if (Log.isDebug()) Log.debug("   calleeTargets %s.%s%s -> %d target(s) of %d impl(s)",
                ct.owner, ct.name, ct.desc, out.size(), concreteImplementations(ct.owner).size());
        // Always include the declared target too: an interface can have a default body.
        if (out.isEmpty() || graph.nodes().contains(self)) out.add(self);
        return out;
    }

    /** Concrete implementations of one method declared on an interface/abstract class. */
    private List<MethodId> implMethods(MethodId m) {
        List<MethodId> out = new ArrayList<>();
        for (String impl : concreteImplementations(m.owner())) {
            MethodId id = new MethodId(impl, m.name(), m.desc());
            if (graph.nodes().contains(id)) out.add(id);
        }
        return out;
    }

    private List<String> supertypesOf(String internal) {
        List<String> out = new ArrayList<>();
        Deque<String> work = new ArrayDeque<>();
        work.add(internal);
        Set<String> seen = new HashSet<>();
        while (!work.isEmpty()) {
            String cur = work.poll();
            if (!seen.add(cur)) continue;
            ClassInfo ci = cp.get(cur);
            if (ci == null) continue;
            if (ci.superName() != null) { out.add(ci.superName()); work.add(ci.superName()); }
            for (String i : ci.interfaces()) { out.add(i); work.add(i); }
        }
        return out;
    }

    /** Concrete classes that implement {@code iface}, cached. */
    private List<String> concreteImplementations(String iface) {
        return implIndex.computeIfAbsent(iface, k -> {
            List<String> out = new ArrayList<>();
            for (ClassInfo sub : cp.allClasses()) {
                if (sub.isInterface() || sub.isAbstract()) continue;
                if (isSubtype(sub.name(), k)) out.add(sub.name());
            }
            return List.copyOf(out);
        });
    }

    private boolean isSubtype(String sub, String sup) {
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

    /** Per-method taint result for a specific tainted-parameter set (argument indexes, 0-based). */
    private MethodTaint local(MethodId m, BitSet taintedArgs) {
        ClassInfo ci = cp.get(m.owner());
        if (ci == null) return null;
        // A method may be inherited: resolve to the class that actually declares the body.
        String decl = m.owner();
        MethodSig sig = ci.method(m.name(), m.desc());
        if (sig == null) {
            for (String sup : supertypesOf(m.owner())) {
                ClassInfo sc = cp.get(sup);
                if (sc == null) continue;
                MethodSig s = sc.method(m.name(), m.desc());
                if (s != null) { decl = sup; sig = s; break; }
            }
        }
        if (sig == null) {
            if (Log.isDebug()) Log.debug("  local no sig: %s supers=%s", m.display(), supertypesOf(m.owner()));
            return null;
        }
        if (!sig.hasCode()) return new MethodTaint();
        byte[] bytes = cp.bytesOf(decl);
        if (bytes == null) { if (Log.isDebug()) Log.debug("  local no bytes: %s", decl); return null; }

        ClassNode cn = new ClassNode();
        new ClassReader(bytes).accept(cn, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        MethodNode mn = null;
        for (MethodNode x : cn.methods) if (x.name.equals(m.name()) && x.desc.equals(m.desc())) { mn = x; break; }
        if (mn == null) { if (Log.isDebug()) Log.debug("  local no node: %s in %s", m.display(), decl); return null; }
        if (mn.instructions.size() == 0) return new MethodTaint();

        // Map argument index -> JVM local slot: instance methods skip slot 0 for `this`, and
        // long/double arguments occupy two slots.
        BitSet taintedLocals = new BitSet();
        Type[] args = Type.getArgumentTypes(m.desc());
        int slot = (mn.access & Opcodes.ACC_STATIC) != 0 ? 0 : 1;
        for (int a = 0; a < args.length; a++) {
            if (taintedArgs.get(a)) taintedLocals.set(slot);
            slot += args[a].getSize();
        }
        if (taintedLocals.isEmpty()) {
            MethodTaint empty = new MethodTaint();
            return empty;
        }

        MethodTaint out = new MethodTaint();
        try {
            Analyzer<TVal> analyzer = new Analyzer<>(new TInterp(this, taintedLocals));
            Frame<TVal>[] frames = analyzer.analyze(cn.name, mn);
            int idx = 0;
            for (AbstractInsnNode insn : mn.instructions) {
                Frame<TVal> f = frames != null && idx < frames.length ? frames[idx] : null;
                if (f == null) { idx++; continue; }
                if (insn instanceof MethodInsnNode mi) {
                    int nargs = Type.getArgumentTypes(mi.desc).length;
                    int need = nargs + 1;
                    BitSet positions = new BitSet();
                    boolean any = false;
                    if (f.getStackSize() >= need) {
                        int start = f.getStackSize() - need;
                        for (int i = 0; i < need; i++) {
                            TVal v = f.getStack(start + i);
                            if (v != null && v.tainted) {
                                any = true;
                                if (i > 0) positions.set(i - 1);
                            }
                        }
                    }
                    out.calls.add(new CallTaint(mi.owner, mi.name, mi.desc, any, positions));
                    if (Log.isDebug() && any) {
                        Log.debug("  tainted call in %s: %s.%s%s positions=%s", m.shortDisplay(),
                                mi.owner, mi.name, mi.desc, positions);
                    }
                }
                int op = insn.getOpcode();
                if (op >= Opcodes.IRETURN && op <= Opcodes.ARETURN) {
                    TVal v = f.getStackSize() > 0 ? f.getStack(f.getStackSize() - 1) : null;
                    if (v != null && v.tainted) out.returnsTainted = true;
                }
                idx++;
            }
        } catch (Exception e) {
            Log.debug("Taint dataflow failed for %s: %s", m.display(), e.getMessage());
            return null;
        }
        return out;
    }

    // ------------------------------------------------------------------ interpreter

    static final class TVal implements Value {
        final boolean tainted;
        private final int size;
        TVal(boolean tainted, int size) { this.tainted = tainted; this.size = size; }
        static final TVal CLEAN = new TVal(false, 1);
        static final TVal TAINT = new TVal(true, 1);
        static TVal of(boolean t, int size) {
            // `size` 0 means void — ASM compares return-value sizes strictly, so it must stay 0.
            if (size == 0) return new TVal(false, 0);
            return new TVal(t, size);
        }
        @Override public int getSize() { return size; }
        @Override public boolean equals(Object o) { return o instanceof TVal v && v.tainted == tainted && v.size == size; }
        @Override public int hashCode() { return (tainted ? 1 : 0) * 31 + size; }
    }

    private static final class TInterp extends Interpreter<TVal> {
        private final TaintEngine engine;
        private final BitSet taintedParams;

        TInterp(TaintEngine engine, BitSet taintedParams) {
            super(Opcodes.ASM9);
            this.engine = engine;
            this.taintedParams = taintedParams;
        }

        @Override public TVal newValue(Type t) {
            if (t == null) return TVal.CLEAN;
            // ASM treats a null value as "nothing on the stack". For a void return this is
            // mandatory: Analyzer stores it as the frame's returnValue and a non-null value makes
            // every plain RETURN fail with "Incompatible return type".
            if (t.getSort() == Type.VOID) return null;
            return TVal.of(false, t.getSize());
        }

        @Override public TVal newOperation(AbstractInsnNode insn) { return TVal.CLEAN; }

        @Override
        public TVal copyOperation(AbstractInsnNode insn, TVal v) {
            // Loading a local: if it is a tainted parameter, the value is tainted.
            if (insn.getOpcode() == Opcodes.ILOAD || insn.getOpcode() == Opcodes.LLOAD
                    || insn.getOpcode() == Opcodes.FLOAD || insn.getOpcode() == Opcodes.DLOAD
                    || insn.getOpcode() == Opcodes.ALOAD) {
                VarInsnNode vi = (VarInsnNode) insn;
                if (taintedParams.get(vi.var)) return TVal.of(true, v.getSize());
            }
            return v;
        }

        @Override
        public TVal unaryOperation(AbstractInsnNode insn, TVal v) {
            int op = insn.getOpcode();
            if (op == Opcodes.GETFIELD) {
                FieldInsnNode f = (FieldInsnNode) insn;
                boolean t = false;
                if (v.tainted) {
                    BitSet ft = engine.fieldTaint.get(f.owner + "#" + f.name);
                    if (ft != null && !ft.isEmpty()) t = true;
                    if ((f.desc.startsWith("L") || f.desc.startsWith("[")) && v.tainted) t = true;
                }
                return TVal.of(t, Type.getType(f.desc).getSize());
            }
            if (op == Opcodes.CHECKCAST) return v;
            return TVal.of(v.tainted && op != Opcodes.ARRAYLENGTH, v.getSize());
        }

        @Override
        public TVal binaryOperation(AbstractInsnNode insn, TVal a, TVal b) {
            // PUTFIELD is reported here by ASM: `object.field = value`, with a=object, b=value.
            if (insn.getOpcode() == Opcodes.PUTFIELD) {
                FieldInsnNode f = (FieldInsnNode) insn;
                if (b.tainted) engine.fieldTaint.put(f.owner + "#" + f.name, new BitSet(1));
                return TVal.CLEAN;
            }
            return TVal.of(a.tainted || b.tainted, 1);
        }

        @Override
        public TVal ternaryOperation(AbstractInsnNode insn, TVal a, TVal b, TVal c) {
            return TVal.of(a.tainted || b.tainted || c.tainted, 1);
        }

        @Override
        public TVal naryOperation(AbstractInsnNode insn, List<? extends TVal> values) {
            if (!(insn instanceof MethodInsnNode mi)) return TVal.CLEAN;
            boolean anyArgTainted = false;
            for (int i = 1; i < values.size(); i++) {
                if (values.get(i) != null && values.get(i).tainted) { anyArgTainted = true; break; }
            }
            Type ret = Type.getReturnType(mi.desc);
            boolean refReturn = ret.getSort() == Type.OBJECT || ret.getSort() == Type.ARRAY;
            boolean isCtor = "<init>".equals(mi.name);
            // A container/message constructed from or computed over tainted input carries taint.
            boolean resultTainted = anyArgTainted && (refReturn || isCtor);
            if (ret.getSort() == Type.VOID) {
                // ASM discards the naryOperation result for a void call; null is the canonical
                // "no value" and keeps the frame's stack discipline intact.
                return null;
            }
            return TVal.of(resultTainted, ret.getSize());
        }

        @Override public void returnOperation(AbstractInsnNode insn, TVal v, TVal expected) { }

        @Override
        public TVal merge(TVal a, TVal b) {
            if (a == null) return b;
            if (b == null) return a;
            return TVal.of(a.tainted || b.tainted, Math.max(a.getSize(), b.getSize()));
        }
    }
}
