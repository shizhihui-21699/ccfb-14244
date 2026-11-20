package dev.reachmap.analysis;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Abstract value used by the intraprocedural constant propagator.
 *
 * <p>Two kinds of information are needed to make hidden calls visible:
 * <ul>
 *   <li><b>constants</b> — to answer "what class does {@code Class.forName(x)} load here?"</li>
 *   <li><b>declared types</b> — to narrow {@code invokeinterface Foo.m()} to the one concrete
 *       receiver the call site actually holds, instead of every {@code Foo} on the classpath</li>
 * </ul>
 * Both live on the same value. Joins keep a type when the alternatives share it, and keep a
 * constant only when it is identical on both sides, so the analysis stays sound.
 */
public final class ConstValue implements org.objectweb.asm.tree.analysis.Value {

    public enum Kind { UNKNOWN, NULL, STRING, CLASS, METHOD_REF }

    public static final ConstValue UNKNOWN = new ConstValue(Kind.UNKNOWN, null, Collections.emptySet(), null, 1);
    public static final ConstValue NULL = new ConstValue(Kind.NULL, null, Collections.emptySet(), null, 1);

    private final Kind kind;
    private final String value;
    private final Set<String> alternatives; // for CLASS: possible internal names
    private final String staticType;        // declared type (internal name) where known
    private final int size;                 // JVM operand size (2 for long/double)

    private ConstValue(Kind kind, String value, Set<String> alternatives, String staticType, int size) {
        this.kind = kind;
        this.value = value;
        this.alternatives = alternatives;
        this.staticType = staticType;
        this.size = size;
    }

    @Override public int getSize() { return size; }

    public static ConstValue string(String s) {
        return s == null ? NULL : new ConstValue(Kind.STRING, s, Collections.emptySet(),
                "java/lang/String", 1);
    }

    public static ConstValue cls(String internalName) {
        return internalName == null ? UNKNOWN
                : new ConstValue(Kind.CLASS, internalName, Set.of(internalName), "java/lang/Class", 1);
    }

    public static ConstValue clsCandidates(Set<String> names) {
        if (names.isEmpty()) return UNKNOWN;
        if (names.size() == 1) return cls(names.iterator().next());
        return new ConstValue(Kind.CLASS, null, Collections.unmodifiableSet(new LinkedHashSet<>(names)),
                "java/lang/Class", 1);
    }

    public static ConstValue methodRef(String owner, String name, String desc) {
        return new ConstValue(Kind.METHOD_REF, owner + "#" + name + desc, Collections.emptySet(),
                "java/lang/reflect/Method", 1);
    }

    /** Value of a parameter/local of a known declared type, with no constant value. */
    public static ConstValue typed(String internalType) {
        if (internalType == null) return UNKNOWN;
        int size = internalType.equals("J") || internalType.equals("D") ? 2 : 1;
        return new ConstValue(Kind.UNKNOWN, null, Collections.emptySet(), internalType, size);
    }

    /** Value of a primitive of a given operand size (1 or 2), with no constant/type. */
    public static ConstValue primitive(int size) {
        return new ConstValue(Kind.UNKNOWN, null, Collections.emptySet(), null, size);
    }

    public Kind kind() { return kind; }
    public String value() { return value; }
    public Set<String> alternatives() { return alternatives; }
    public String staticType() { return staticType; }

    public boolean isString() { return kind == Kind.STRING; }
    public boolean isClass() { return kind == Kind.CLASS; }
    public boolean isMethodRef() { return kind == Kind.METHOD_REF; }

    /** Internal class name when exactly one is known. */
    public String className() {
        return kind == Kind.CLASS && value != null ? value : null;
    }

    public Set<String> classNames() {
        if (kind != Kind.CLASS) return Collections.emptySet();
        if (value != null) return Set.of(value);
        return alternatives;
    }

    public boolean isKnown() { return kind != Kind.UNKNOWN; }

    /** Keeps this value but records a more specific declared type (e.g. after checkcast). */
    public ConstValue withType(String t) {
        if (t == null || Objects.equals(t, staticType)) return this;
        return new ConstValue(kind, value, alternatives, t, size);
    }

    /** Merge for control-flow joins. */
    public ConstValue merge(ConstValue o) {
        if (o == null) return this;
        String type = Objects.equals(staticType, o.staticType) ? staticType : null;
        if (equals(o)) return this;
        if (kind == Kind.CLASS && o.kind == Kind.CLASS) {
            LinkedHashSet<String> all = new LinkedHashSet<>(classNames());
            all.addAll(o.classNames());
            return new ConstValue(Kind.CLASS, null, Collections.unmodifiableSet(all), type, 1);
        }
        if (kind == Kind.UNKNOWN && o.kind == Kind.UNKNOWN && type != null) return typed(type);
        if (kind == Kind.UNKNOWN && o.kind == Kind.UNKNOWN) return UNKNOWN;
        return new ConstValue(Kind.UNKNOWN, null, Collections.emptySet(), type, size);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof ConstValue c)) return false;
        return kind == c.kind && Objects.equals(value, c.value) && alternatives.equals(c.alternatives)
                && Objects.equals(staticType, c.staticType);
    }

    @Override
    public int hashCode() { return Objects.hash(kind, value, alternatives, staticType); }

    @Override
    public String toString() {
        String t = staticType == null ? "" : staticType.replace('/', '.');
        return switch (kind) {
            case UNKNOWN -> "?" + (t.isEmpty() ? "" : ":" + t);
            case NULL -> "null" + (t.isEmpty() ? "" : ":" + t);
            case STRING -> "\"" + value + "\"";
            case CLASS -> "class " + (value != null ? value : alternatives);
            case METHOD_REF -> "methodref " + value;
        };
    }
}
