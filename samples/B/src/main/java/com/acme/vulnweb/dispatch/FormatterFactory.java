package com.acme.vulnweb.dispatch;

/** Constructs the implementation lazily; nothing else in the app names {@link MarkupFormatter}. */
public final class FormatterFactory {
    private FormatterFactory() {}

    public static Formatter create() {
        return new MarkupFormatter();
    }

    private static Formatter cached;

    public static Formatter shared() {
        if (cached == null) cached = create();
        return cached;
    }
}
