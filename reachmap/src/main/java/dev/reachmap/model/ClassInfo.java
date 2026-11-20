package dev.reachmap.model;

import java.util.List;

/** Lightweight class description gathered without parsing method bodies. */
public final class ClassInfo {
    public enum Source { APP, LIB }

    private final String name;          // internal name a/b/C
    private final int access;
    private final String superName;     // may be null
    private final List<String> interfaces;
    private final List<Anno> annotations;
    private final List<MethodSig> methods;
    private final List<FieldInfo> fields;
    private final Source source;
    private final String artifact;      // artifactId or jar file name
    private final String origin;        // jar path or class dir
    private final String sourceFile;
    private final String outerClass;

    public ClassInfo(String name, int access, String superName, List<String> interfaces,
                     List<Anno> annotations, List<MethodSig> methods, List<FieldInfo> fields,
                     Source source, String artifact, String origin, String sourceFile, String outerClass) {
        this.name = name;
        this.access = access;
        this.superName = superName;
        this.interfaces = List.copyOf(interfaces);
        this.annotations = List.copyOf(annotations);
        this.methods = List.copyOf(methods);
        this.fields = List.copyOf(fields);
        this.source = source;
        this.artifact = artifact;
        this.origin = origin;
        this.sourceFile = sourceFile;
        this.outerClass = outerClass;
    }

    public String name() { return name; }
    public int access() { return access; }
    public String superName() { return superName; }
    public List<String> interfaces() { return interfaces; }
    public List<Anno> annotations() { return annotations; }
    public List<MethodSig> methods() { return methods; }
    public List<FieldInfo> fields() { return fields; }
    public Source source() { return source; }
    public String artifact() { return artifact; }
    public String origin() { return origin; }
    public String sourceFile() { return sourceFile; }
    public String outerClass() { return outerClass; }

    public boolean isInterface() { return (access & 0x0200) != 0; }
    public boolean isAbstract() { return (access & 0x0400) != 0; }
    public boolean isFinal() { return (access & 0x0010) != 0; }
    public boolean isPublic() { return (access & 0x0001) != 0; }
    public boolean isAnnotation() { return (access & 0x2000) != 0; }
    public boolean isEnum() { return (access & 0x4000) != 0; }
    public boolean isSynthetic() { return (access & 0x1000) != 0; }
    public boolean isApp() { return source == Source.APP; }

    public String displayName() { return name.replace('/', '.'); }

    public Anno annotation(String dottedName) {
        for (Anno a : annotations) if (a.className().equals(dottedName)) return a;
        return null;
    }

    public boolean hasAnnotation(String dottedName) { return annotation(dottedName) != null; }

    public boolean hasAnnotationSimple(String simple) {
        for (Anno a : annotations) if (a.simpleName().equals(simple)) return true;
        return false;
    }

    public MethodSig method(String name, String desc) {
        for (MethodSig m : methods) if (m.name().equals(name) && m.desc().equals(desc)) return m;
        return null;
    }

    public FieldInfo field(String name) {
        for (FieldInfo f : fields) if (f.name().equals(name)) return f;
        return null;
    }

    public boolean hasClinit() {
        for (MethodSig m : methods) if ("<clinit>".equals(m.name())) return true;
        return false;
    }

    @Override
    public String toString() { return displayName(); }
}
