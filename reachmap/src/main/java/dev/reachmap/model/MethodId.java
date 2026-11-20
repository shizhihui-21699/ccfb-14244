package dev.reachmap.model;

import java.util.Objects;

/** Fully-qualified reference to a method: owner (internal name), name and JVM descriptor. */
public record MethodId(String owner, String name, String desc) implements Comparable<MethodId> {

    public MethodId {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(desc, "desc");
    }

    public static MethodId ofClass(String internalName, String name, String desc) {
        return new MethodId(internalName, name, desc);
    }

    public boolean isConstructor() {
        return "<init>".equals(name) || "<clinit>".equals(name);
    }

    public String displayClass() {
        return owner.replace('/', '.');
    }

    /** e.g. {@code com.acme.Foo.bar(java.lang.String)}. */
    public String display() {
        String cls = owner.replace('/', '.');
        if ("<init>".equals(name)) return cls + ".<init>" + dev.reachmap.util.Text.describeArgs(desc);
        if ("<clinit>".equals(name)) return cls + ".<clinit>";
        return cls + "." + name + dev.reachmap.util.Text.describeArgs(desc);
    }

    public String shortDisplay() {
        String simple = dev.reachmap.util.Text.simpleName(owner);
        return simple + "." + name + dev.reachmap.util.Text.describeArgs(desc);
    }

    @Override
    public int compareTo(MethodId o) {
        int c = owner.compareTo(o.owner);
        if (c != 0) return c;
        c = name.compareTo(o.name);
        if (c != 0) return c;
        return desc.compareTo(o.desc);
    }
}
