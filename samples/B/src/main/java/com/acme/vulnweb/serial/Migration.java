package com.acme.vulnweb.serial;

import org.apache.commons.collections.functors.InvokerTransformer;

/**
 * The vulnerable hop behind {@code SessionState.readObject}.
 *
 * <p>Note the shape: no endpoint calls this class. It is reachable only through a
 * deserialization callback chain — the kind of path a bytecode-only call graph misses.
 */
public final class Migration {

    private Migration() {}

    public static String apply(String value) {
        // commons-collections 3.2.1 gadget primitive (CVE-2015-6420 family)
        InvokerTransformer t = new InvokerTransformer("trim", null, null);
        Object out = t.transform(value == null ? "" : value);
        return String.valueOf(out);
    }
}
