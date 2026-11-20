package dev.reachmap.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal dependency-free JSON reader/writer.
 *
 * <p>ReachMap deliberately keeps its runtime dependencies to ASM only, so that it can be dropped
 * into any CI image and analyze arbitrary project dependency sets without classpath conflicts.
 * The subset supported here is plain JSON (objects, arrays, strings, numbers, booleans, null).
 */
public final class Json {
    private Json() {}

    // ---------------------------------------------------------------- parsing

    public static Object parseFile(Path p) throws IOException {
        return parse(Files.readString(p, StandardCharsets.UTF_8));
    }

    public static Object parse(String s) {
        Parser p = new Parser(s);
        Object v = p.value();
        p.skipWs();
        if (!p.eof()) throw new JsonException("trailing content at offset " + p.pos);
        return v;
    }

    public static final class JsonException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public JsonException(String m) { super(m); }
    }

    private static final class Parser {
        final String s;
        int pos;
        Parser(String s) { this.s = s; }

        boolean eof() { return pos >= s.length(); }
        void skipWs() { while (!eof() && Character.isWhitespace(s.charAt(pos))) pos++; }
        char peek() { if (eof()) throw new JsonException("unexpected end of input"); return s.charAt(pos); }
        char take() { char c = peek(); pos++; return c; }
        void expect(char c) { if (take() != c) throw new JsonException("expected '" + c + "' at " + (pos - 1)); }

        Object value() {
            skipWs();
            char c = peek();
            switch (c) {
                case '{': return object();
                case '[': return array();
                case '"': return string();
                case 't': literal("true"); return Boolean.TRUE;
                case 'f': literal("false"); return Boolean.FALSE;
                case 'n': literal("null"); return null;
                default: return number();
            }
        }

        void literal(String lit) {
            if (!s.startsWith(lit, pos)) throw new JsonException("bad literal at " + pos);
            pos += lit.length();
        }

        Map<String, Object> object() {
            expect('{');
            Map<String, Object> m = new LinkedHashMap<>();
            skipWs();
            if (peek() == '}') { pos++; return m; }
            while (true) {
                skipWs();
                String k = string();
                skipWs();
                expect(':');
                m.put(k, value());
                skipWs();
                char c = take();
                if (c == '}') return m;
                if (c != ',') throw new JsonException("expected ',' or '}' at " + (pos - 1));
            }
        }

        List<Object> array() {
            expect('[');
            List<Object> a = new ArrayList<>();
            skipWs();
            if (peek() == ']') { pos++; return a; }
            while (true) {
                a.add(value());
                skipWs();
                char c = take();
                if (c == ']') return a;
                if (c != ',') throw new JsonException("expected ',' or ']' at " + (pos - 1));
            }
        }

        String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = take();
                if (c == '"') return sb.toString();
                if (c != '\\') { sb.append(c); continue; }
                char e = take();
                switch (e) {
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> {
                        if (pos + 4 > s.length()) throw new JsonException("bad \\u escape");
                        sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                        pos += 4;
                    }
                    default -> throw new JsonException("bad escape \\" + e);
                }
            }
        }

        Object number() {
            int start = pos;
            while (!eof() && "-+.eE0123456789".indexOf(s.charAt(pos)) >= 0) pos++;
            String t = s.substring(start, pos);
            if (t.isEmpty()) throw new JsonException("unexpected character '" + peek() + "' at " + pos);
            if (t.contains(".") || t.contains("e") || t.contains("E")) return Double.parseDouble(t);
            try { return Long.parseLong(t); } catch (NumberFormatException ex) { return Double.parseDouble(t); }
        }
    }

    // ---------------------------------------------------------------- writing

    public static String write(Object v) {
        StringBuilder sb = new StringBuilder();
        write(sb, v, -1, 0);
        return sb.toString();
    }

    public static String pretty(Object v) {
        StringBuilder sb = new StringBuilder();
        write(sb, v, 2, 0);
        sb.append('\n');
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object v, int indent, int depth) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof String str) { quote(sb, str); return; }
        if (v instanceof Boolean || v instanceof Integer || v instanceof Long || v instanceof Short
                || v instanceof Byte) { sb.append(v); return; }
        if (v instanceof Number n) {
            double d = n.doubleValue();
            if (d == Math.rint(d) && !Double.isInfinite(d) && Math.abs(d) < 1e15) sb.append((long) d);
            else sb.append(d);
            return;
        }
        if (v instanceof Map<?, ?> m) {
            if (m.isEmpty()) { sb.append("{}"); return; }
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                newline(sb, indent, depth + 1);
                quote(sb, String.valueOf(e.getKey()));
                sb.append(':');
                if (indent > 0) sb.append(' ');
                write(sb, e.getValue(), indent, depth + 1);
            }
            newline(sb, indent, depth);
            sb.append('}');
            return;
        }
        if (v instanceof Iterable<?> it) {
            boolean any = it.iterator().hasNext();
            if (!any) { sb.append("[]"); return; }
            sb.append('[');
            boolean first = true;
            for (Object o : it) {
                if (!first) sb.append(',');
                first = false;
                newline(sb, indent, depth + 1);
                write(sb, o, indent, depth + 1);
            }
            newline(sb, indent, depth);
            sb.append(']');
            return;
        }
        if (v instanceof Object[] arr) {
            List<Object> l = new ArrayList<>(arr.length);
            java.util.Collections.addAll(l, arr);
            write(sb, l, indent, depth);
            return;
        }
        quote(sb, String.valueOf(v));
    }

    private static void newline(StringBuilder sb, int indent, int depth) {
        if (indent < 0) return;
        sb.append('\n');
        sb.append(" ".repeat(indent * depth));
    }

    private static void quote(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20 || c > 0x7e) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        sb.append('"');
    }

    // ---------------------------------------------------------------- typed views

    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : Map.of();
    }

    @SuppressWarnings("unchecked")
    public static List<Object> arr(Object o) {
        return o instanceof List ? (List<Object>) o : List.of();
    }

    public static String str(Object o, String def) {
        return o instanceof String s ? s : def;
    }

    public static String str(Map<String, Object> m, String k, String def) {
        return str(m.get(k), def);
    }

    public static boolean bool(Map<String, Object> m, String k, boolean def) {
        Object v = m.get(k);
        return v instanceof Boolean b ? b : def;
    }

    public static long num(Map<String, Object> m, String k, long def) {
        Object v = m.get(k);
        return v instanceof Number n ? n.longValue() : def;
    }

    public static List<String> strList(Map<String, Object> m, String k) {
        List<String> out = new ArrayList<>();
        for (Object o : arr(m.get(k))) if (o instanceof String s) out.add(s);
        return out;
    }

    public static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put(String.valueOf(kv[i]), kv[i + 1]);
        return m;
    }

    public static List<Object> list(Object... items) {
        List<Object> l = new ArrayList<>(items.length);
        java.util.Collections.addAll(l, items);
        return l;
    }
}
