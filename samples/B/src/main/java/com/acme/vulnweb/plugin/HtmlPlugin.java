package com.acme.vulnweb.plugin;

import org.apache.commons.collections.functors.InvokerTransformer;

/**
 * Vulnerable plugin: uses commons-collections 3.2.1 {@code InvokerTransformer}, whose
 * {@code transform} is the gadget entry flagged by CVE-2015-6420 / the commons-collections
 * deserialization family.
 *
 * <p>Nothing in the controller calls this class. The only thing that connects it is the class
 * name in {@code plugin.properties}, which is what makes it a reachability test for
 * configuration-driven dispatch.
 */
public class HtmlPlugin implements TextPlugin {

    private final InvokerTransformer transformer = new InvokerTransformer("toString", null, null);

    @Override
    public String transform(String input) {
        Object out = transformer.transform(input);
        return "<div>" + out + "</div>";
    }
}
