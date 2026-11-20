package com.acme.vulnweb.dispatch;

import org.apache.commons.collections.functors.InvokerTransformer;

/** The sole implementation; constructed only from {@link FormatterFactory}. */
public class MarkupFormatter implements Formatter {
    @Override
    public String format(String input) {
        // commons-collections gadget primitive, reached through the interface dispatch above.
        InvokerTransformer t = new InvokerTransformer("trim", null, null);
        return String.valueOf(t.transform(input));
    }
}
