package dev.reachmap.model;

import java.util.List;

/** Field metadata including annotations and constant value. */
public record FieldInfo(String name, String desc, int access, List<Anno> annotations,
                        Object constantValue, String signature) {

    public boolean isStatic() { return (access & 0x0008) != 0; }
    public boolean isFinal() { return (access & 0x0010) != 0; }
    public boolean isPublic() { return (access & 0x0001) != 0; }
    public boolean isPrivate() { return (access & 0x0002) != 0; }

    public Anno annotation(String dottedName) {
        for (Anno a : annotations) if (a.className().equals(dottedName)) return a;
        return null;
    }

    public boolean hasAnnotation(String dottedName) { return annotation(dottedName) != null; }

    public boolean hasAnnotationSimple(String simple) {
        for (Anno a : annotations) if (a.simpleName().equals(simple)) return true;
        return false;
    }

    /** Internal name of the field type if it is an object type, else null. */
    public String objectType() {
        if (desc.startsWith("L") && desc.endsWith(";")) return desc.substring(1, desc.length() - 1);
        return null;
    }
}
