package com.acme.vulnweb.plugin;

/**
 * Plugin contract. Implementations are selected at runtime by a name in plugin.properties,
 * never by a call site in application code.
 */
public interface TextPlugin {
    String transform(String input);
}
