package com.acme.cleanapp;

import org.yaml.snakeyaml.Yaml;

import java.io.StringReader;

/**
 * Safe use of snakeyaml: it parses a document that comes from a bundled resource, not from
 * request input, and the result is only used as a plain map.
 *
 * <p>Reachable, so the snakeyaml entry {@code Yaml.load} is on a path — but the boolean flag on
 * the call chain records that the data source is not attacker-controlled.
 */
public class BundleLoader {

    public java.util.Map<String, Object> loadBundled(String bundledYaml) {
        Yaml yaml = new Yaml();
        Object o = yaml.load(new StringReader(bundledYaml));
        return o instanceof java.util.Map ? (java.util.Map<String, Object>) o : java.util.Map.of();
    }
}
