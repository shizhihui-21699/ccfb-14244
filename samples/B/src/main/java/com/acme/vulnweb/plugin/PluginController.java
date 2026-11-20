package com.acme.vulnweb.plugin;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint that renders through the configured plugin.
 *
 * <p>The call {@code registry.get().transform(...)} is an interface dispatch whose receiver was
 * loaded reflectively. This is the highest-value hidden edge in the sample: the vulnerable
 * {@code HtmlPlugin} is only reachable if the analyzer connects the config value to the class.
 */
@RestController
public class PluginController {

    private final PluginRegistry registry = new PluginRegistry();

    @GetMapping("/render")
    public String render(@RequestParam("text") String text) {
        return registry.get().transform(text);
    }
}
