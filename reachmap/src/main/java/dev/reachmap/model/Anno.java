package dev.reachmap.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Parsed annotation, values normalized to JSON-friendly Java objects. */
public final class Anno {
    /** Internal descriptor, e.g. {@code Lorg/springframework/web/bind/annotation/GetMapping;}. */
    private final String desc;
    private final Map<String, Object> values;

    public Anno(String desc, Map<String, Object> values) {
        this.desc = desc;
        this.values = values;
    }

    public String desc() { return desc; }

    /** Dotted annotation class name. */
    public String className() {
        String d = desc;
        if (d.startsWith("L") && d.endsWith(";")) d = d.substring(1, d.length() - 1);
        return d.replace('/', '.');
    }

    public String simpleName() {
        String n = className();
        int i = n.lastIndexOf('.');
        return i >= 0 ? n.substring(i + 1) : n;
    }

    public Map<String, Object> values() { return values; }

    public Object value(String key) { return values.get(key); }

    public String stringValue(String key) {
        Object v = values.get(key);
        return v instanceof String s ? s : null;
    }

    @Override
    public String toString() { return "@" + className() + values; }

    /** Builder used by the bytecode reader. */
    public static final class Builder {
        private final String desc;
        private final Map<String, Object> values = new LinkedHashMap<>();

        public Builder(String desc) { this.desc = desc; }

        public void put(String key, Object value) { values.put(key, value); }

        public Anno build() { return new Anno(desc, Map.copyOf(values)); }

        public static Object normalizeArray(List<Object> values) {
            List<Object> out = new ArrayList<>(values.size());
            for (Object v : values) out.add(normalize(v));
            return out;
        }

        public static Object normalize(Object v) {
            if (v instanceof Anno) return ((Anno) v).className();
            if (v instanceof Anno[] arr) {
                List<String> l = new ArrayList<>();
                for (Anno a : arr) l.add(a.className());
                return l;
            }
            if (v instanceof dev.reachmap.model.ClassInfo) return ((ClassInfo) v).name();
            return v;
        }
    }
}
