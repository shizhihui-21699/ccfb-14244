package dev.reachmap.util;

import java.util.Collection;
import java.util.StringJoiner;

/** Text helpers shared by reports and analysis code. */
public final class Text {
    private Text() {}

    public static String cls(String internalName) {
        return internalName == null ? "<none>" : internalName.replace('/', '.');
    }

    public static String join(Collection<String> parts, String sep) {
        StringJoiner j = new StringJoiner(sep);
        for (String p : parts) j.add(p);
        return j.toString();
    }

    public static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }

    public static String percent(long num, long den) {
        return den == 0 ? "n/a" : String.format("%.1f%%", 100.0 * num / den);
    }

    /** Parses a JVM method descriptor's argument count, excluding the receiver. */
    public static int argCount(String desc) {
        int count = 0;
        int i = 1;
        while (desc.charAt(i) != ')') {
            char c = desc.charAt(i);
            if (c == '[') { i++; continue; }
            if (c == 'L') {
                i = desc.indexOf(';', i) + 1;
            } else {
                i++;
            }
            count++;
        }
        return count;
    }

    /** Human readable method descriptor, e.g. {@code (java.lang.String, int)}. */
    public static String describeArgs(String desc) {
        StringJoiner j = new StringJoiner(", ", "(", ")");
        int i = 1;
        while (desc.charAt(i) != ')') {
            int start = i;
            while (desc.charAt(i) == '[') i++;
            char c = desc.charAt(i);
            String t;
            if (c == 'L') {
                int end = desc.indexOf(';', i);
                t = desc.substring(i + 1, end).replace('/', '.');
                i = end + 1;
            } else {
                t = switch (c) {
                    case 'Z' -> "boolean"; case 'B' -> "byte"; case 'C' -> "char";
                    case 'S' -> "short"; case 'I' -> "int"; case 'J' -> "long";
                    case 'F' -> "float"; case 'D' -> "double"; default -> String.valueOf(c);
                };
                i++;
            }
            int dims = 0;
            for (int k = start; k < i && desc.charAt(k) == '['; k++) dims++;
            j.add(t + "[]".repeat(dims));
        }
        return j.toString();
    }

    public static String simpleName(String internalName) {
        if (internalName == null) return "<none>";
        String s = internalName;
        int i = Math.max(s.lastIndexOf('/'), s.lastIndexOf('$'));
        return i >= 0 ? s.substring(i + 1) : s;
    }
}
