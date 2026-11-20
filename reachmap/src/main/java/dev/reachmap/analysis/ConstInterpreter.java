package dev.reachmap.analysis;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.Interpreter;

import java.util.*;

/**
 * Forward constant/type propagator over one method body.
 *
 * <p>It tracks two things, both of which are needed to recover hidden call relations without
 * becoming unsound:
 * <ul>
 *   <li>string and {@code Class} constants, to resolve reflection</li>
 *   <li>the declared type of reference values, to narrow interface dispatch</li>
 * </ul>
 * Anything it cannot prove degrades to UNKNOWN, so it never invents a call target.
 */
final class ConstInterpreter extends Interpreter<ConstValue> {

    private final Map<String, String> staticStringFields;

    ConstInterpreter(Map<String, String> staticStringFields) {
        super(Opcodes.ASM9);
        this.staticStringFields = staticStringFields;
    }

    private static String internalName(Type t) {
        return t.getSort() == Type.OBJECT ? t.getInternalName()
                : t.getSort() == Type.ARRAY ? t.getDescriptor() : null;
    }

    @Override
    public ConstValue newValue(Type type) {
        if (type == null) return ConstValue.UNKNOWN;
        // ASM stores the method's return type value on the frame; a non-null value for a void
        // method makes every plain RETURN fail with "Incompatible return type".
        if (type.getSort() == Type.VOID) return null;
        if (type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY) {
            return ConstValue.typed(internalName(type));
        }
        return ConstValue.primitive(type.getSize());
    }

    /** Declared type of a slot, used for method parameters entering the frame. */
    private ConstValue typedDesc(String desc) {
        Type t = Type.getType(desc);
        return ConstValue.typed(internalName(t));
    }

    @Override
    public ConstValue newOperation(AbstractInsnNode insn) {
        return switch (insn.getOpcode()) {
            case Opcodes.ACONST_NULL -> ConstValue.NULL;
            case Opcodes.LDC -> {
                LdcInsnNode ldc = (LdcInsnNode) insn;
                Object c = ldc.cst;
                if (c instanceof String s) yield ConstValue.string(s);
                if (c instanceof Type t && t.getSort() == Type.OBJECT) yield ConstValue.cls(t.getInternalName());
                if (c instanceof Type t && t.getSort() == Type.ARRAY) yield ConstValue.typed(t.getDescriptor());
                yield ConstValue.UNKNOWN;
            }
            case Opcodes.NEW -> {
                TypeInsnNode t = (TypeInsnNode) insn;
                yield ConstValue.typed(t.desc);
            }
            case Opcodes.GETSTATIC -> {
                FieldInsnNode f = (FieldInsnNode) insn;
                yield staticFieldValue(f);
            }
            default -> ConstValue.UNKNOWN;
        };
    }

    private ConstValue staticFieldValue(FieldInsnNode f) {
        if (f.desc.equals("Ljava/lang/String;")) {
            String v = staticStringFields.get(f.owner.replace('/', '.') + "#" + f.name);
            if (v != null) return ConstValue.string(v);
        }
        if (f.desc.startsWith("L") && f.desc.endsWith(";")) {
            return ConstValue.typed(f.desc.substring(1, f.desc.length() - 1));
        }
        return ConstValue.UNKNOWN;
    }

    @Override public ConstValue copyOperation(AbstractInsnNode insn, ConstValue value) { return value; }

    @Override
    public ConstValue unaryOperation(AbstractInsnNode insn, ConstValue value) {
        int op = insn.getOpcode();
        if (op == Opcodes.GETFIELD) {
            FieldInsnNode f = (FieldInsnNode) insn;
            if (f.desc.equals("Ljava/lang/String;")) return ConstValue.typed("java/lang/String");
            if (f.desc.startsWith("L") && f.desc.endsWith(";")) {
                return ConstValue.typed(f.desc.substring(1, f.desc.length() - 1));
            }
            return ConstValue.UNKNOWN;
        }
        if (op == Opcodes.CHECKCAST) {
            TypeInsnNode t = (TypeInsnNode) insn;
            if (value.isClass() || value.isString()) return value;
            // A checkcast narrows the static receiver type: this is how a call site that checks
            // `instanceof JndiLookup` before dispatch gets its precise target.
            return value.withType(t.desc);
        }
        if (op == Opcodes.NEWARRAY || op == Opcodes.ANEWARRAY) return ConstValue.UNKNOWN;
        return ConstValue.UNKNOWN;
    }

    @Override
    public ConstValue binaryOperation(AbstractInsnNode insn, ConstValue a, ConstValue b) {
        return ConstValue.UNKNOWN;
    }

    @Override
    public ConstValue ternaryOperation(AbstractInsnNode insn, ConstValue a, ConstValue b, ConstValue c) {
        return ConstValue.UNKNOWN;
    }

    @Override
    public ConstValue naryOperation(AbstractInsnNode insn, List<? extends ConstValue> values) {
        int op = insn.getOpcode();
        if (op == Opcodes.MULTIANEWARRAY) return ConstValue.typed(((MultiANewArrayInsnNode) insn).desc);
        if (!(insn instanceof MethodInsnNode m)) return ConstValue.UNKNOWN;

        String owner = m.owner;
        String name = m.name;
        Type ret = Type.getReturnType(m.desc);

        // ---- reflection: class loading
        if ("java/lang/Class".equals(owner) && "forName".equals(name)) {
            ConstValue first = values.isEmpty() ? null : values.get(0);
            if (first != null && first.isString() && first.value() != null) {
                return ConstValue.cls(first.value().replace('.', '/'));
            }
            return ConstValue.typed("java/lang/Class");
        }
        if ("java/lang/ClassLoader".equals(owner) && "loadClass".equals(name)) {
            // instance form: receiver at 0, name at 1; static form: name at 0
            ConstValue arg = values.size() >= 2 ? values.get(1) : (values.isEmpty() ? null : values.get(0));
            if (arg != null && arg.isString() && arg.value() != null) {
                return ConstValue.cls(arg.value().replace('.', '/'));
            }
            return ConstValue.typed("java/lang/Class");
        }

        // ---- reflection: method/constructor handles
        if ("java/lang/Class".equals(owner)
                && ("getMethod".equals(name) || "getDeclaredMethod".equals(name))
                && values.size() >= 2) {
            ConstValue cls = values.get(0);
            ConstValue mname = values.get(1);
            if (cls.isClass() && mname.isString() && mname.value() != null) {
                for (String c : cls.classNames()) return ConstValue.methodRef(c, mname.value(), "");
            }
            return ConstValue.typed("java/lang/reflect/Method");
        }
        if ("java/lang/Class".equals(owner)
                && ("getConstructor".equals(name) || "getDeclaredConstructor".equals(name))
                && !values.isEmpty()) {
            ConstValue cls = values.get(0);
            if (cls.isClass()) {
                for (String c : cls.classNames()) return ConstValue.methodRef(c, "<init>", "");
            }
            return ConstValue.typed("java/lang/reflect/Constructor");
        }

        // ---- conversions that preserve the Class constant
        if ("java/lang/Class".equals(owner) && ("cast".equals(name) || "asSubclass".equals(name))) {
            return values.get(0);
        }

        // ---- anything else: the declared return type is still useful for dispatch narrowing
        if (ret.getSort() == Type.VOID) return null;
        String t = internalName(ret);
        if (t != null) return ConstValue.typed(t);
        return ConstValue.primitive(ret.getSize());
    }

    @Override
    public void returnOperation(AbstractInsnNode insn, ConstValue value, ConstValue expected) { }

    @Override
    public ConstValue merge(ConstValue a, ConstValue b) {
        if (a == null) return b;
        if (b == null) return a;
        return a.merge(b);
    }
}
