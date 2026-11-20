package dev.reachmap.analysis;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Facts extracted from one method body, in a form the graph builder can consume. */
public final class MethodFacts {

    /** A call instruction (or a call implied by a reflective handle). */
    public static final class Call {
        public final String owner;
        public final String name;
        public final String desc;
        public final int opcode;
        public final boolean intf;
        public final int line;
        /** Static types of receiver + arguments as inferred by the constant/type pass. */
        public final List<String> argTypes;
        /** Constant values of receiver + arguments where known. */
        public final List<ConstValue> argConsts;
        /** Set when this "call" is really the expansion of a reflective lookup. */
        public final boolean reflective;
        public final String reflectiveKind;

        public Call(String owner, String name, String desc, int opcode, boolean intf, int line,
                    List<String> argTypes, List<ConstValue> argConsts, boolean reflective, String reflectiveKind) {
            this.owner = owner;
            this.name = name;
            this.desc = desc;
            this.opcode = opcode;
            this.intf = intf;
            this.line = line;
            // argTypes/argConsts may legitimately contain null (unknown static type / uninitialised
            // frame slot), so they cannot go through the null-rejecting List.copyOf.
            this.argTypes = argTypes == null ? List.of()
                    : java.util.Collections.unmodifiableList(new ArrayList<>(argTypes));
            this.argConsts = argConsts == null ? List.of()
                    : java.util.Collections.unmodifiableList(new ArrayList<>(argConsts));
            this.reflective = reflective;
            this.reflectiveKind = reflectiveKind;
        }

        public boolean isInvokeVirtualLike() {
            return opcode == org.objectweb.asm.Opcodes.INVOKEVIRTUAL
                    || opcode == org.objectweb.asm.Opcodes.INVOKEINTERFACE;
        }

        public boolean isInvokeStatic() { return opcode == org.objectweb.asm.Opcodes.INVOKESTATIC; }
        public boolean isInvokeSpecial() { return opcode == org.objectweb.asm.Opcodes.INVOKESPECIAL; }

        public ConstValue constantArg(int i) {
            int idx = i + 1; // skip receiver
            return idx < argConsts.size() ? argConsts.get(idx) : ConstValue.UNKNOWN;
        }

        public String argType(int i) {
            int idx = i + 1;
            return idx < argTypes.size() ? argTypes.get(idx) : null;
        }
    }

    /** A string constant anywhere in the body, used for config-key heuristics. */
    public record StringConst(String value, int line) {}

    public final List<Call> calls = new ArrayList<>();
    public final Set<String> newTypes = new LinkedHashSet<>();
    public final List<StringConst> strings = new ArrayList<>();
    public final Set<String> classLiterals = new LinkedHashSet<>();
    /** Class names that this method may load or instantiate reflectively (resolved or not). */
    public final Set<String> reflectiveClassCandidates = new LinkedHashSet<>();
    /** True if the body contains an unresolvable reflective/indirect dispatch. */
    public boolean hasUnresolvedDynamicCall = false;
    public final List<String> unresolvedReason = new ArrayList<>();
    /** Descriptor of the method this fact set belongs to (for lambda/method-ref bookkeeping). */
    public String methodDesc;
    public boolean readsSerializedStream = false;
    public boolean writesSerializedStream = false;

    public void addCall(Call c) { calls.add(c); }

    public void unresolved(String reason) {
        hasUnresolvedDynamicCall = true;
        if (!unresolvedReason.contains(reason)) unresolvedReason.add(reason);
    }

    public boolean isEmpty() {
        return calls.isEmpty() && newTypes.isEmpty() && !hasUnresolvedDynamicCall;
    }
}
