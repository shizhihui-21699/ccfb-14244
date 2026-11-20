package dev.reachmap.analysis;

import java.util.ArrayList;
import java.util.List;

/** A place where the analysis had to stop or guess, recorded for the uncertainty ledger. */
public final class Uncertainty {

    public enum Category {
        REFLECTION("reflection"),
        DEPENDENCY_INJECTION("dependency-injection"),
        DYNAMIC_PROXY("dynamic-proxy"),
        SERIALIZATION("serialization"),
        CONFIGURATION("configuration-driven"),
        LAMBDA("lambda"),
        SERVICE_LOADER("service-loader"),
        MISSING_CLASS("missing-class"),
        NATIVE("native"),
        DATAFLOW("dataflow"),
        CROSS_MODULE("cross-module"),
        FRAMEWORK("framework-callback"),
        DISPATCH("wide-dispatch"),
        DEPTH("depth-limit");

        private final String label;
        Category(String label) { this.label = label; }
        public String label() { return label; }
    }

    public enum Severity {
        /** Could hide a real path to vulnerable code. Worth human review. */
        HIGH,
        /** May add spurious edges; bounded impact on reachable/unreachable verdicts. */
        MEDIUM,
        /** Informational. */
        LOW
    }

    private final Category category;
    private final Severity severity;
    private final String location;       // class.method:line
    private final String description;
    private final String method;         // internal "owner#name desc" of the containing method
    private final String artifact;
    private final boolean inAppCode;

    public Uncertainty(Category category, Severity severity, String location, String description,
                       String method, String artifact, boolean inAppCode) {
        this.category = category;
        this.severity = severity;
        this.location = location;
        this.description = description;
        this.method = method;
        this.artifact = artifact;
        this.inAppCode = inAppCode;
    }

    public Category category() { return category; }
    public Severity severity() { return severity; }
    public String location() { return location; }
    public String description() { return description; }
    public String method() { return method; }
    public String artifact() { return artifact; }
    public boolean inAppCode() { return inAppCode; }

    @Override
    public String toString() {
        return "[" + severity + "/" + category.label() + "] " + location + ": " + description;
    }
}
