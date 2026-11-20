package dev.reachmap.model;

import java.util.List;

/** Method signature and metadata, always available without parsing the method body. */
public record MethodSig(String name, String desc, int access, List<Anno> annotations,
                        List<List<Anno>> parameterAnnotations, List<String> parameterNames,
                        List<String> exceptions, boolean hasCode) {

    public boolean isStatic() { return (access & 0x0008) != 0; }
    public boolean isPrivate() { return (access & 0x0002) != 0; }
    public boolean isPublic() { return (access & 0x0001) != 0; }
    public boolean isProtected() { return (access & 0x0004) != 0; }
    public boolean isAbstract() { return (access & 0x0400) != 0; }
    public boolean isNative() { return (access & 0x0100) != 0; }
    public boolean isFinal() { return (access & 0x0010) != 0; }
    public boolean isSynchronized() { return (access & 0x0020) != 0; }
    public boolean isBridge() { return (access & 0x0040) != 0; }
    public boolean isSynthetic() { return (access & 0x1000) != 0; }
    public boolean isConstructor() { return "<init>".equals(name); }

    public Anno annotation(String dottedName) {
        for (Anno a : annotations) if (a.className().equals(dottedName)) return a;
        return null;
    }

    public boolean hasAnnotation(String dottedName) { return annotation(dottedName) != null; }

    public boolean hasAnnotationSimple(String simple) {
        for (Anno a : annotations) if (a.simpleName().equals(simple)) return true;
        return false;
    }

    public Anno parameterAnnotation(int index, String dottedName) {
        if (index < 0 || index >= parameterAnnotations.size()) return null;
        for (Anno a : parameterAnnotations.get(index)) if (a.className().equals(dottedName)) return a;
        return null;
    }

    public boolean hasAnyParameterAnnotation(String... simpleNames) {
        for (List<Anno> annos : parameterAnnotations) {
            for (Anno a : annos) {
                for (String s : simpleNames) if (a.simpleName().equals(s)) return true;
            }
        }
        return false;
    }
}
