package com.acme.vulnweb.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Loads the configured plugin reflectively.
 *
 * <p>Two reflective hops: {@code Class.forName} on a value read from configuration (the constant
 * propagator cannot see through {@code Properties.getProperty}, so this is a real "configured,
 * not constant" case), then {@code newInstance}. The analyzer must connect the configured class
 * to {@link TextPlugin#transform} as a framework/config-driven callback.
 */
public class PluginRegistry {

    private TextPlugin plugin;

    public synchronized TextPlugin get() {
        if (plugin == null) plugin = load();
        return plugin;
    }

    private TextPlugin load() {
        Properties props = new Properties();
        try (InputStream in = getClass().getResourceAsStream("/plugin.properties")) {
            props.load(in);
            String className = props.getProperty("plugin.class");
            Class<?> cls = Class.forName(className);
            return (TextPlugin) cls.getDeclaredConstructor().newInstance();
        } catch (IOException | ReflectiveOperationException e) {
            throw new IllegalStateException("plugin load failed", e);
        }
    }
}
