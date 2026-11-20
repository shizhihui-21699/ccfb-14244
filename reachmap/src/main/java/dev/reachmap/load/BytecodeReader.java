package dev.reachmap.load;

import dev.reachmap.model.*;
import org.objectweb.asm.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Reads {@link ClassInfo} (and later method bodies) from class file bytes with ASM. */
public final class BytecodeReader {

    private BytecodeReader() {}

    /** Header-only class parse: no instruction decoding, so it is fast enough to index whole jars. */
    public static ClassInfo readHeader(byte[] bytes, ClassInfo.Source source, String artifact,
                                       String origin, String outerClassHint) {
        HeaderVisitor v = new HeaderVisitor(source, artifact, origin, outerClassHint);
        new ClassReader(bytes).accept(v, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return v.build();
    }

    /** Full method body parse: dispatches every interesting instruction to the visitor. */
    public static void readBody(byte[] bytes, String targetMethod, String targetDesc, MethodBodyVisitor v) {
        new ClassReader(bytes).accept(new BodyVisitor(targetMethod, targetDesc, v), ClassReader.SKIP_FRAMES);
    }

    public static byte[] readAll(InputStream in) throws IOException {
        try (in) { return in.readAllBytes(); }
    }

    // ------------------------------------------------------------------ header visitor

    private static final class HeaderVisitor extends ClassVisitor {
        private final ClassInfo.Source source;
        private final String artifact;
        private final String origin;
        private String outerClassHint;
        private String name;
        private int access;
        private String superName;
        private List<String> interfaces = new ArrayList<>();
        private final List<Anno> classAnnos = new ArrayList<>();
        private final List<MethodSig> methods = new ArrayList<>();
        private final List<FieldInfo> fields = new ArrayList<>();
        private String sourceFile;
        private String outerFromInner;

        HeaderVisitor(ClassInfo.Source source, String artifact, String origin, String outerClassHint) {
            super(Opcodes.ASM9);
            this.source = source;
            this.artifact = artifact;
            this.origin = origin;
            this.outerClassHint = outerClassHint;
        }

        @Override
        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            this.name = name;
            this.access = access;
            this.superName = superName;
            if (interfaces != null) this.interfaces = List.of(interfaces);
        }

        @Override
        public void visitSource(String source, String debug) { this.sourceFile = source; }

        @Override
        public void visitOuterClass(String owner, String name, String desc) { this.outerFromInner = owner; }

        @Override
        public void visitInnerClass(String name, String outerName, String innerName, int access) {
            if (name.equals(this.name) && outerName != null) this.outerFromInner = outerName;
        }

        @Override
        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            return new AnnoBuilder(descriptor, classAnnos);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
            final List<Anno> annos = new ArrayList<>();
            final List<List<Anno>> paramAnnos = new ArrayList<>();
            final List<String> paramNames = new ArrayList<>();
            final List<String> ex = exceptions == null ? List.of() : List.of(exceptions);
            return new MethodVisitor(Opcodes.ASM9) {
                @Override
                public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
                    return new AnnoBuilder(descriptor, annos);
                }

                @Override
                public AnnotationVisitor visitParameterAnnotation(int parameter, String descriptor, boolean visible) {
                    while (paramAnnos.size() <= parameter) paramAnnos.add(new ArrayList<>());
                    return new AnnoBuilder(descriptor, paramAnnos.get(parameter));
                }

                @Override
                public void visitParameter(String pname, int paccess) { paramNames.add(pname); }

                @Override
                public void visitEnd() {
                    boolean hasCode = (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) == 0;
                    List<List<Anno>> pa = new ArrayList<>(paramAnnos.size());
                    for (List<Anno> l : paramAnnos) pa.add(List.copyOf(l));
                    methods.add(new MethodSig(name, desc, access, List.copyOf(annos),
                            List.copyOf(pa), List.copyOf(paramNames), ex, hasCode));
                }
            };
        }

        @Override
        public FieldVisitor visitField(int access, String name, String desc, String signature, Object value) {
            final List<Anno> annos = new ArrayList<>();
            return new FieldVisitor(Opcodes.ASM9) {
                @Override
                public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
                    return new AnnoBuilder(descriptor, annos);
                }

                @Override
                public void visitEnd() {
                    fields.add(new FieldInfo(name, desc, access, List.copyOf(annos), value, signature));
                }
            };
        }

        ClassInfo build() {
            String outer = outerFromInner != null ? outerFromInner : outerClassHint;
            return new ClassInfo(name, access, superName, interfaces, classAnnos, methods, fields,
                    source, artifact, origin, sourceFile, outer);
        }
    }

    /** Collects one annotation (including nested annotations and arrays) and emits it on visitEnd. */
    private static final class AnnoBuilder extends AnnotationVisitor {
        private final String desc;
        private final List<Anno> sink;
        private final Map<String, Object> values = new LinkedHashMap<>();

        AnnoBuilder(String desc, List<Anno> sink) {
            super(Opcodes.ASM9);
            this.desc = desc;
            this.sink = sink;
        }

        private static String descToClass(String d) {
            if (d.startsWith("L") && d.endsWith(";")) d = d.substring(1, d.length() - 1);
            return d.replace('/', '.');
        }

        @Override
        public void visit(String name, Object value) {
            values.put(name == null ? "value" : name, value instanceof Type t ? t.getClassName() : value);
        }

        @Override
        public void visitEnum(String name, String descriptor, String value) {
            values.put(name == null ? "value" : name, value);
        }

        @Override
        public AnnotationVisitor visitAnnotation(String name, String descriptor) {
            final String key = name == null ? "value" : name;
            final Map<String, Object> nested = new LinkedHashMap<>();
            return new AnnotationVisitor(Opcodes.ASM9) {
                @Override public void visit(String n, Object v) { nested.put(n == null ? "value" : n, v instanceof Type t ? t.getClassName() : v); }
                @Override public void visitEnum(String n, String d, String v) { nested.put(n == null ? "value" : n, v); }
                @Override public AnnotationVisitor visitAnnotation(String n, String d) { return this; }
                @Override public AnnotationVisitor visitArray(String n) { return this; }
                @Override public void visitEnd() {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("@type", descToClass(descriptor));
                    m.putAll(nested);
                    Object prev = values.get(key);
                    if (prev instanceof List<?> l && !(values.get("@multi:" + key) != null)) { /* keep simple */ }
                    values.put(key, m);
                }
            };
        }

        @Override
        public AnnotationVisitor visitArray(String name) {
            final String key = name == null ? "value" : name;
            final List<Object> items = new ArrayList<>();
            return new AnnotationVisitor(Opcodes.ASM9) {
                @Override public void visit(String n, Object v) { items.add(v instanceof Type t ? t.getClassName() : v); }
                @Override public void visitEnum(String n, String d, String v) { items.add(v); }
                @Override public AnnotationVisitor visitAnnotation(String n, String descriptor) {
                    final Map<String, Object> nested = new LinkedHashMap<>();
                    nested.put("@type", descToClass(descriptor));
                    items.add(nested);
                    return new AnnotationVisitor(Opcodes.ASM9) {
                        @Override public void visit(String nn, Object vv) { nested.put(nn == null ? "value" : nn, vv instanceof Type t ? t.getClassName() : vv); }
                        @Override public void visitEnum(String nn, String dd, String vv) { nested.put(nn == null ? "value" : nn, vv); }
                        @Override public AnnotationVisitor visitArray(String nn) { return this; }
                    };
                }
                @Override public void visitEnd() { values.put(key, List.copyOf(items)); }
            };
        }

        @Override
        public void visitEnd() {
            sink.add(new Anno(desc, Map.copyOf(values)));
        }
    }

    // ------------------------------------------------------------------ body visitor

    private static final class BodyVisitor extends ClassVisitor {
        private final String targetMethod;
        private final String targetDesc;
        private final MethodBodyVisitor v;

        BodyVisitor(String targetMethod, String targetDesc, MethodBodyVisitor v) {
            super(Opcodes.ASM9);
            this.targetMethod = targetMethod;
            this.targetDesc = targetDesc;
            this.v = v;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
            if (!name.equals(targetMethod) || !desc.equals(targetDesc)) return null;
            return new MethodVisitor(Opcodes.ASM9) {
                private int line = -1;

                @Override public void visitLineNumber(int l, Label start) { line = l; v.visitLine(l); }

                @Override
                public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
                    v.visitCall(owner, name, desc, itf, opcode, line);
                }

                @Override
                public void visitFieldInsn(int opcode, String owner, String name, String desc) {
                    boolean write = opcode == Opcodes.PUTFIELD || opcode == Opcodes.PUTSTATIC;
                    v.visitFieldAccess(owner, name, desc, write, line);
                }

                @Override
                public void visitTypeInsn(int opcode, String type) {
                    if (opcode == Opcodes.NEW) v.visitNewType(type, line);
                    else if (opcode == Opcodes.CHECKCAST || opcode == Opcodes.INSTANCEOF) v.visitTypeConstant(type, opcode, line);
                }

                @Override
                public void visitLdcInsn(Object value) {
                    v.visitLdcConstant(value instanceof Type t ? t.getInternalName() : value, line);
                }

                @Override
                public void visitInvokeDynamicInsn(String name, String desc, Handle bsm, Object... bsmArgs) {
                    // lambda / method reference / string concat bootstrap
                    for (Object a : bsmArgs) {
                        if (a instanceof Handle h) {
                            v.visitMethodHandle(h.getOwner(), h.getName(), h.getDesc(), h.getTag(), line);
                        }
                    }
                }

                @Override public void visitInsn(int opcode) {
                    if (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) v.visitReturn();
                    else if (opcode == Opcodes.ATHROW) v.visitThrow();
                }

                @Override public void visitLocalVariable(String name, String desc, String signature, Label start, Label end, int index) {
                    v.visitLocalVariable(index, name, desc);
                }
            };
        }
    }

    /** Callback interface so analysis code does not depend on ASM directly. */
    public interface MethodBodyVisitor {
        default void visitCall(String owner, String name, String desc, boolean itf, int opcode, int line) {}
        default void visitFieldAccess(String owner, String name, String desc, boolean isWrite, int line) {}
        default void visitTypeConstant(String internalName, int opcode, int line) {}
        default void visitLdcConstant(Object value, int line) {}
        default void visitNewType(String internalName, int line) {}
        default void visitMethodHandle(String owner, String name, String desc, int tag, int line) {}
        default void visitLocalVariable(int index, String name, String desc) {}
        default void visitLine(int line) {}
        default void visitReturn() {}
        default void visitThrow() {}
    }
}
