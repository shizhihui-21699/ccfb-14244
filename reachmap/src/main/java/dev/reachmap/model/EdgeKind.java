package dev.reachmap.model;

/** How a call edge came to exist, and how much it can be trusted. */
public enum EdgeKind {
    /** invokestatic / invokespecial / private / constructor: JVM resolves this exactly. */
    DIRECT_EXACT("direct", Confidence.EXACT),
    /** Virtual/interface call with exactly one possible implementation on the classpath. */
    DISPATCH_EXACT("dispatch-exact", Confidence.EXACT),
    /** Virtual/interface call narrowed to a small set of concrete implementations. */
    DISPATCH_NARROWED("dispatch-narrowed", Confidence.NARROWED),
    /** Virtual/interface call with many concrete implementations (class hierarchy analysis). */
    DISPATCH_WIDE("dispatch-wide", Confidence.WIDE),
    /** Interface method bound to the single Spring/CDI bean implementing it. */
    DI_BINDING("di-binding", Confidence.NARROWED),
    /** Interface method with several bean candidates; qualifier/primary did not decide. */
    DI_AMBIGUOUS("di-ambiguous", Confidence.WIDE),
    /** Reflection where class and method names were constant and resolvable. */
    REFLECT_CONSTANT("reflection-constant", Confidence.NARROWED),
    /** Reflection resolved through configuration values (class name in a config file). */
    REFLECT_CONFIGURED("reflection-configured", Confidence.NARROWED),
    /** ServiceLoader / META-INF/services declared provider. */
    SERVICE_PROVIDER("service-provider", Confidence.NARROWED),
    /** Callback invoked by a framework: serialization, proxy handler, Runnable, etc. */
    FRAMEWORK_CALLBACK("framework-callback", Confidence.NARROWED),
    /** Callback whose concrete receiver cannot be determined (proxy/reflection). */
    CALLBACK_OPEN("callback-open", Confidence.UNRESOLVED),
    /** Passed in from configuration that names a class (log4j appender, yaml tag, ...). */
    CONFIG_DRIVEN("config-driven", Confidence.NARROWED),
    /** Class initializer run when the class is first actively used. */
    STATIC_INIT("static-init", Confidence.EXACT),
    /** Bridge/synthetic accessor invoked from an enclosing method. */
    SYNTHETIC("synthetic", Confidence.EXACT);

    private final String label;
    private final Confidence base;

    EdgeKind(String label, Confidence base) {
        this.label = label;
        this.base = base;
    }

    public String label() { return label; }
    public Confidence baseConfidence() { return base; }

    /** Confidence levels, ordered from strongest to weakest. */
    public enum Confidence {
        EXACT(0, "EXACT"),
        NARROWED(1, "NARROWED"),
        WIDE(2, "WIDE"),
        UNRESOLVED(3, "UNRESOLVED");

        private final int rank;
        private final String label;

        Confidence(int rank, String label) { this.rank = rank; this.label = label; }

        public int rank() { return rank; }
        public String label() { return label; }

        public static Confidence worst(Confidence a, Confidence b) {
            return a.rank >= b.rank ? a : b;
        }

        public static Confidence fromLabel(String s) {
            for (Confidence c : values()) if (c.label.equalsIgnoreCase(s)) return c;
            return WIDE;
        }
    }
}
