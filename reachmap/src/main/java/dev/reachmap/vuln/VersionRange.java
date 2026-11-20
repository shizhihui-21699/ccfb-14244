package dev.reachmap.vuln;

import java.util.ArrayList;
import java.util.List;

/**
 * Parses Maven-style version ranges such as {@code [2.0,2.17.0)}, {@code (,1.2.5]},
 * {@code 2.14.1} (exact) and {@code >=2.0 <2.15}. Used only to decide whether the analyzed
 * dependency version is in the vulnerable range, which is what separates "patch your library"
 * from "trace the path".
 */
public final class VersionRange {

    private final List<String> spec;

    private VersionRange(List<String> spec) { this.spec = spec; }

    public static VersionRange parse(String text) {
        List<String> spec = new ArrayList<>();
        if (text == null || text.isBlank()) return new VersionRange(spec);
        String t = text.trim();
        if (t.contains(",") && !t.contains(" ")) {
            // Maven range syntax
            char first = t.charAt(0);
            char last = t.charAt(t.length() - 1);
            boolean lowerInc = first == '[';
            boolean upperInc = last == ']';
            String inner = t.substring(1, t.length() - 1);
            String[] parts = inner.split(",", -1);
            String lo = parts.length > 0 ? parts[0].trim() : "";
            String hi = parts.length > 1 ? parts[1].trim() : "";
            if (!lo.isEmpty()) spec.add((lowerInc ? ">=" : ">") + lo);
            if (!hi.isEmpty()) spec.add((upperInc ? "<=" : "<") + hi);
        } else if (t.startsWith(">") || t.startsWith("<")) {
            for (String part : t.split("\\s+")) {
                if (!part.isBlank()) spec.add(part);
            }
        } else {
            spec.add("=" + t);
        }
        return new VersionRange(spec);
    }

    public boolean isEmpty() { return spec.isEmpty(); }

    public boolean contains(String version) {
        if (version == null || version.isBlank()) return false;
        if (spec.isEmpty()) return true;
        String v = normalize(version);
        for (String clause : spec) {
            clause = clause.trim();
            if (clause.startsWith(">=")) { if (compare(v, normalize(clause.substring(2))) < 0) return false; }
            else if (clause.startsWith("<=")) { if (compare(v, normalize(clause.substring(2))) > 0) return false; }
            else if (clause.startsWith(">")) { if (compare(v, normalize(clause.substring(1))) <= 0) return false; }
            else if (clause.startsWith("<")) { if (compare(v, normalize(clause.substring(1))) >= 0) return false; }
            else if (clause.startsWith("=")) { if (compare(v, normalize(clause.substring(1))) != 0) return false; }
            else if (compare(v, normalize(clause)) < 0) return false;
        }
        return true;
    }

    private static String normalize(String v) {
        String s = v.trim();
        // strip classifiers/suffixes like -jre, -Final? Keep them for compare but treat + as build.
        int plus = s.indexOf('+');
        if (plus > 0) s = s.substring(0, plus);
        return s;
    }

    /** Numeric component comparison with qualifier fallback. */
    static int compare(String a, String b) {
        String[] as = a.split("[.\\-_]");
        String[] bs = b.split("[.\\-_]");
        int n = Math.max(as.length, bs.length);
        for (int i = 0; i < n; i++) {
            String x = i < as.length ? as[i] : "0";
            String y = i < bs.length ? bs[i] : "0";
            boolean xn = x.matches("\\d+");
            boolean yn = y.matches("\\d+");
            int c;
            if (xn && yn) {
                c = Long.compare(Long.parseLong(x), Long.parseLong(y));
            } else if (xn) {
                c = 1; // numeric component outranks a qualifier
            } else if (yn) {
                c = -1;
            } else {
                c = x.compareToIgnoreCase(y);
            }
            if (c != 0) return c;
        }
        return 0;
    }

    @Override
    public String toString() { return String.join(" ", spec); }
}
