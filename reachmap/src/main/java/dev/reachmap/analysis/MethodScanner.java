package dev.reachmap.analysis;

import dev.reachmap.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.*;

/**
 * Extracts {@link MethodFacts} from one method body: call sites, constructed types, constants and
 * unresolved dynamic dispatches.
 *
 * <p>Constant values come from a small forward dataflow ({@link ConstInterpreter}) so that
 * reflective calls with statically known names can be resolved instead of being written off as
 * unknown. Anything the dataflow cannot prove stays UNKNOWN, which later becomes an explicit
 * "uncertain" mark in the report rather than a silent assumption.
 */
public final class MethodScanner {

    private final Map<String, String> staticStringFields;

    public MethodScanner(Map<String, String> staticStringFields) {
        this.staticStringFields = staticStringFields;
    }

    public MethodFacts scan(byte[] classBytes, String methodName, String methodDesc) {
        MethodFacts facts = new MethodFacts();
        facts.methodDesc = methodDesc;
        ClassNode cn = new ClassNode();
        new ClassReader(classBytes).accept(cn, ClassReader.SKIP_FRAMES);
        MethodNode mn = null;
        for (MethodNode m : cn.methods) {
            if (m.name.equals(methodName) && m.desc.equals(methodDesc)) { mn = m; break; }
        }
        if (mn == null || mn.instructions.size() == 0) return facts;

        Frame<ConstValue>[] frames;
        try {
            Analyzer<ConstValue> analyzer = new Analyzer<>(new ConstInterpreter(staticStringFields));
            frames = analyzer.analyze(cn.name, mn);
        } catch (AnalyzerException e) {
            // A malformed/obfuscated body must not abort the whole analysis.
            Log.debug("Dataflow failed for %s.%s%s: %s", cn.name, methodName, methodDesc, e.getMessage());
            frames = null;
            facts.unresolved("dataflow failed: " + e.getMessage());
        }

        Map<LabelNode, Integer> lineAt = new HashMap<>();
        int line = -1;
        for (AbstractInsnNode insn : mn.instructions) {
            if (insn instanceof LineNumberNode ln) line = ln.line;
            lineAt.putIfAbsent(insn instanceof LabelNode l ? l : null, line);
            int idx = mn.instructions.indexOf(insn);
            Frame<ConstValue> frame = frames != null && idx < frames.length ? frames[idx] : null;

            if (insn instanceof MethodInsnNode mi) {
                handleInvoke(facts, cn, mi, frame, line);
            } else if (insn instanceof InvokeDynamicInsnNode indy) {
                handleIndy(facts, indy, line);
            } else if (insn instanceof TypeInsnNode ti && ti.getOpcode() == Opcodes.NEW) {
                facts.newTypes.add(ti.desc);
            } else if (insn instanceof LdcInsnNode ldc) {
                if (ldc.cst instanceof String s && s.length() < 512) facts.strings.add(new MethodFacts.StringConst(s, line));
                else if (ldc.cst instanceof Type t && t.getSort() == Type.OBJECT) facts.classLiterals.add(t.getInternalName());
            } else if (insn instanceof FieldInsnNode fi && fi.getOpcode() == Opcodes.GETSTATIC) {
                if (fi.desc.equals("Ljava/lang/String;")) {
                    String v = staticStringFields.get(fi.owner.replace('/', '.') + "#" + fi.name);
                    if (v != null) facts.strings.add(new MethodFacts.StringConst(v, line));
                }
            }
        }
        detectSerializationStreams(facts);
        return facts;
    }

    private static void detectSerializationStreams(MethodFacts facts) {
        for (MethodFacts.Call c : facts.calls) {
            if ("java/io/ObjectInputStream".equals(c.owner)
                    && (c.name.equals("readObject") || c.name.equals("readUnshared"))) {
                facts.readsSerializedStream = true;
            }
            if ("java/io/ObjectOutputStream".equals(c.owner) && c.name.equals("writeObject")) {
                facts.writesSerializedStream = true;
            }
        }
    }

    private void handleInvoke(MethodFacts facts, ClassNode cn, MethodInsnNode mi,
                              Frame<ConstValue> frame, int line) {
        List<ConstValue> operands = operandValues(mi, frame);
        List<String> types = operandTypes(mi, frame);
        facts.addCall(new MethodFacts.Call(mi.owner, mi.name, mi.desc, mi.getOpcode(), mi.itf, line,
                types, operands, false, null));

        String owner = mi.owner;
        String name = mi.name;

        // ------------------------------------------------ reflection resolution
        if ("java/lang/Class".equals(owner) && ("forName".equals(name) || "newInstance".equals(name))) {
            ConstValue cls = operands.isEmpty() ? ConstValue.UNKNOWN : operands.get(0);
            for (String c : cls.classNames()) facts.reflectiveClassCandidates.add(c);
            if ("newInstance".equals(name)) {
                for (String c : cls.classNames()) {
                    facts.addCall(new MethodFacts.Call(c, "<init>", "()V", Opcodes.INVOKESPECIAL, false, line,
                            List.of(), List.of(), true, "Class.newInstance"));
                }
            }
            if (!cls.isKnown()) {
                facts.unresolved("Class.forName/newInstance with non-constant class name at line " + line);
            }
            return;
        }

        if ("java/lang/invoke/MethodHandles$Lookup".equals(owner)
                && name.startsWith("find")) {
            ConstValue target = operands.size() >= 3 ? operands.get(1) : ConstValue.UNKNOWN;
            ConstValue targetName = operands.size() >= 3 ? operands.get(2) : ConstValue.UNKNOWN;
            if (target.isClass() && targetName.isString() && targetName.value() != null) {
                for (String c : target.classNames()) {
                    facts.reflectiveClassCandidates.add(c);
                    facts.addCall(new MethodFacts.Call(c, targetName.value(), inferDesc(name), Opcodes.INVOKESTATIC, false,
                            line, List.of(), List.of(), true, "MethodHandles." + name));
                }
            } else {
                facts.unresolved("MethodHandles." + name + " with non-constant target at line " + line);
            }
            return;
        }

        if ("java/lang/reflect/Method".equals(owner) && name.equals("invoke")) {
            ConstValue recv = operands.isEmpty() ? ConstValue.UNKNOWN : operands.get(0);
            if (recv.isMethodRef()) {
                String v = recv.value();               // owner#name+desc
                int hash = v.indexOf('#');
                String c = v.substring(0, hash);
                String rest = v.substring(hash + 1);
                String mname = rest.startsWith("<init>") ? "<init>" : rest.substring(0, rest.indexOf('(') < 0 ? rest.length() : rest.indexOf('('));
                facts.reflectiveClassCandidates.add(c);
                facts.addCall(new MethodFacts.Call(c, mname, null, Opcodes.INVOKEVIRTUAL, false, line,
                        List.of(), List.of(), true, "Method.invoke"));
            } else {
                facts.unresolved("Method.invoke on a Method value that could not be resolved at line " + line);
            }
            return;
        }

        if ("java/lang/reflect/Constructor".equals(owner) && name.equals("newInstance")) {
            ConstValue recv = operands.isEmpty() ? ConstValue.UNKNOWN : operands.get(0);
            if (recv.isMethodRef()) {
                String c = recv.value().substring(0, recv.value().indexOf('#'));
                facts.reflectiveClassCandidates.add(c);
                facts.addCall(new MethodFacts.Call(c, "<init>", null, Opcodes.INVOKESPECIAL, false, line,
                        List.of(), List.of(), true, "Constructor.newInstance"));
            } else {
                facts.unresolved("Constructor.newInstance with unresolved constructor at line " + line);
            }
            return;
        }

        if ("java/io/ObjectInputStream".equals(owner) && name.equals("readObject")) {
            // The concrete receiver type is unknown; the deserialization callback model in the
            // graph builder attaches readObject() implementations of reachable classes.
            facts.unresolved("ObjectInputStream.readObject: concrete deserialized types not statically known at line " + line);
        }

        // ------------------------------------------------ configuration-driven class names
        if ("java/lang/ClassLoader".equals(owner) && name.equals("loadClass")) {
            ConstValue arg = operands.size() >= 2 ? operands.get(1) : (operands.isEmpty() ? ConstValue.UNKNOWN : operands.get(0));
            if (arg.isString() && arg.value() != null) {
                facts.reflectiveClassCandidates.add(arg.value().replace('.', '/'));
            } else {
                facts.unresolved("ClassLoader.loadClass with non-constant name at line " + line);
            }
        }
    }

    private void handleIndy(MethodFacts facts, InvokeDynamicInsnNode indy, int line) {
        // Lambda / method reference: the bootstrap refers to the implementation method, which is
        // an exact edge (the synthetic lambda body or the referenced method).
        for (Object a : indy.bsmArgs) {
            if (a instanceof org.objectweb.asm.Handle h) {
                String cowner = h.getOwner();
                String cname = h.getName();
                String cdesc = h.getDesc();
                int op = switch (h.getTag()) {
                    case Opcodes.H_NEWINVOKESPECIAL -> Opcodes.INVOKESPECIAL;
                    case Opcodes.H_INVOKESTATIC -> Opcodes.INVOKESTATIC;
                    case Opcodes.H_INVOKEINTERFACE -> Opcodes.INVOKEINTERFACE;
                    default -> Opcodes.INVOKEVIRTUAL;
                };
                facts.addCall(new MethodFacts.Call(cowner, cname, cdesc, op, op == Opcodes.INVOKEINTERFACE, line,
                        List.of(), List.of(), op != Opcodes.INVOKESTATIC, "lambda/method-reference"));
            }
        }
    }

    private static String inferDesc(String findKind) {
        // findStatic/findVirtual/findSpecial/findConstructor: descriptor is not on the stack as a
        // constant in general; return null to mean "resolve by name and arity later".
        return null;
    }

    private static List<ConstValue> operandValues(MethodInsnNode mi, Frame<ConstValue> frame) {
        int nargs = dev.reachmap.util.Text.argCount(mi.desc);
        int need = nargs + 1;
        List<ConstValue> out = new ArrayList<>(need);
        if (frame == null) return out;
        int stackSize = frame.getStackSize();
        if (stackSize < need) return out;
        int start = stackSize - need;
        for (int i = 0; i < need; i++) out.add(frame.getStack(start + i));
        return out;
    }

    private static List<String> operandTypes(MethodInsnNode mi, Frame<ConstValue> frame) {
        int nargs = dev.reachmap.util.Text.argCount(mi.desc);
        int need = nargs + 1;
        List<String> out = new ArrayList<>(need);
        if (frame == null) return out;
        int stackSize = frame.getStackSize();
        if (stackSize < need) return out;
        int start = stackSize - need;
        for (int i = 0; i < need; i++) {
            ConstValue v = frame.getStack(start + i);
            out.add(v == null ? null : v.staticType());
        }
        return out;
    }
}
