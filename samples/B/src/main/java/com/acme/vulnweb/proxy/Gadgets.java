package com.acme.vulnweb.proxy;

import org.apache.commons.collections.functors.InvokerTransformer;

/** Vulnerable target reached only from the proxy handler. */
public final class Gadgets {

    private Gadgets() {}

    public static String transform(String v) {
        InvokerTransformer t = new InvokerTransformer("toUpperCase", null, null);
        return String.valueOf(t.transform(v));
    }
}
