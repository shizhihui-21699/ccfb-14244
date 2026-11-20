package com.acme.vulnweb.plugin;

/** Harmless plugin, the one actually wired in the "safe" profile. */
public class PlainPlugin implements TextPlugin {
    @Override
    public String transform(String input) {
        return input;
    }
}
