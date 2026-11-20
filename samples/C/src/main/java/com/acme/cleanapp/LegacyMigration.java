package com.acme.cleanapp;

import org.apache.commons.collections.functors.InvokerTransformer;

/**
 * Dead code that *would* be dangerous.
 *
 * <p>{@code legacyTransform} calls the commons-collections gadget primitive, but nothing calls
 * {@code legacyTransform}: it is private and unreferenced. This is the single most important
 * negative case in the suite, because a bytecode scanner that greps for sink usage would flag it.
 */
public final class LegacyMigration {

    private LegacyMigration() {}

    private static String legacyTransform(String input) {
        InvokerTransformer t = new InvokerTransformer("toString", null, null);
        return String.valueOf(t.transform(input));
    }

    static void unusedButPublic(String s) {
        // also never called
        System.out.println(s);
    }
}
