package dev.reachmap.util;

import java.io.PrintStream;

/** Small logger; everything goes to stderr so that machine output on stdout stays clean. */
public final class Log {
    public enum Level { DEBUG, INFO, WARN, ERROR }

    private static Level level = Level.INFO;
    private static final PrintStream OUT = System.err;
    private static final long START = System.nanoTime();

    private Log() {}

    public static void setLevel(Level l) { level = l; }

    public static boolean isDebug() { return level.ordinal() <= Level.DEBUG.ordinal(); }

    public static void debug(String fmt, Object... args) { log(Level.DEBUG, fmt, args); }
    public static void info(String fmt, Object... args) { log(Level.INFO, fmt, args); }
    public static void warn(String fmt, Object... args) { log(Level.WARN, fmt, args); }
    public static void error(String fmt, Object... args) { log(Level.ERROR, fmt, args); }

    public static void log(Level l, String fmt, Object... args) {
        if (l.ordinal() < level.ordinal()) return;
        String msg = args.length == 0 ? fmt : String.format(fmt, args);
        double secs = (System.nanoTime() - START) / 1e9;
        synchronized (OUT) {
            OUT.printf("[%7.2fs] %-5s %s%n", secs, l, msg);
        }
    }

    public static double elapsedSeconds() { return (System.nanoTime() - START) / 1e9; }
}
