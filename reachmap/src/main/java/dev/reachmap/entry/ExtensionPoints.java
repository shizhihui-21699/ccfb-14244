package dev.reachmap.entry;

import java.util.*;

/**
 * Known framework extension points: "if the app registers an implementation of X, the framework
 * will call it at a certain point".
 *
 * <p>This is a curated table rather than a general rule because a general rule ("any interface a
 * library calls") would drag in the entire library universe. Each entry states the interface, how
 * the framework discovers implementers, and which method is the callback the framework invokes.
 * When a table row matches the analyzed classpath, the analyzer adds a framework-callback edge and
 * labels it as such in the proof, so a reader can see the assumption.
 */
public final class ExtensionPoints {

    /** How the framework discovers the implementation. */
    public enum Discovery {
        ANNOTATION,     // class carries a framework annotation (e.g. @Plugin)
        SUBTYPE,        // class implements/extends a known interface or base class
        SERVICE_FILE,   // META-INF/services
        CONFIG_VALUE    // class name appears in a configuration file
    }

    public record Extension(String framework, String contract, Discovery discovery,
                            String annotationOrService, List<String> callbacks, String note) {}

    public static final List<Extension> KNOWN = List.of(
            // ---- log4j2 plugin system: PluginManager.collectPlugins instantiates @Plugin classes
            new Extension("log4j2", "org/apache/logging/log4j/core/lookup/StrLookup", Discovery.ANNOTATION,
                    "org/apache/logging/log4j/core/config/plugins/Plugin",
                    List.of("lookup"),
                    "log4j2 @Plugin(category=Lookup) classes are instantiated and dispatched by prefix"),
            new Extension("log4j2", "org/apache/logging/log4j/core/Appender", Discovery.ANNOTATION,
                    "org/apache/logging/log4j/core/config/plugins/Plugin", List.of("append"), "log4j2 appender plugins"),
            new Extension("log4j2", "org/apache/logging/log4j/core/Layout", Discovery.ANNOTATION,
                    "org/apache/logging/log4j/core/config/plugins/Plugin", List.of("encode"), "log4j2 layout plugins"),
            new Extension("log4j2", "org/apache/logging/log4j/core/pattern/PatternConverter", Discovery.ANNOTATION,
                    "org/apache/logging/log4j/core/config/plugins/Plugin", List.of("format"), "log4j2 pattern converters"),

            // ---- servlet container lifecycle
            new Extension("servlet", "javax/servlet/ServletContextListener", Discovery.SUBTYPE, null,
                    List.of("contextInitialized"), "servlet listeners called by the container at startup"),
            new Extension("servlet", "jakarta/servlet/ServletContextListener", Discovery.SUBTYPE, null,
                    List.of("contextInitialized"), "servlet listeners called by the container at startup"),
            new Extension("servlet", "javax/servlet/Filter", Discovery.SUBTYPE, null,
                    List.of("doFilter"), "servlet filters called for every request"),
            new Extension("servlet", "jakarta/servlet/Filter", Discovery.SUBTYPE, null,
                    List.of("doFilter"), "servlet filters called for every request"),

            // ---- serialization callbacks
            new Extension("java-serialization", "java/io/Serializable", Discovery.SUBTYPE, null,
                    List.of("readObject", "readResolve", "readExternal"), "deserialization callbacks"),
            new Extension("externalizable", "java/io/Externalizable", Discovery.SUBTYPE, null,
                    List.of("readExternal"), "Externalizable deserialization callback"),

            // ---- Spring lifecycle / extension interfaces
            new Extension("spring", "org/springframework/beans/factory/InitializingBean", Discovery.SUBTYPE, null,
                    List.of("afterPropertiesSet"), "Spring calls afterPropertiesSet when a bean is created"),
            new Extension("spring", "org/springframework/beans/factory/DisposableBean", Discovery.SUBTYPE, null,
                    List.of("destroy"), "Spring calls destroy on shutdown"),
            new Extension("spring", "org/springframework/context/ApplicationListener", Discovery.SUBTYPE, null,
                    List.of("onApplicationEvent"), "Spring event listener callback"),
            new Extension("spring", "org/springframework/web/servlet/HandlerInterceptor", Discovery.SUBTYPE, null,
                    List.of("preHandle", "postHandle"), "Spring MVC request interceptor"),
            new Extension("spring", "org/springframework/web/filter/OncePerRequestFilter", Discovery.SUBTYPE, null,
                    List.of("doFilterInternal"), "Spring request filter"),
            new Extension("spring", "org/springframework/boot/CommandLineRunner", Discovery.SUBTYPE, null,
                    List.of("run"), "Spring Boot command line runner"),
            new Extension("spring", "org/springframework/boot/ApplicationRunner", Discovery.SUBTYPE, null,
                    List.of("run"), "Spring Boot application runner"),
            new Extension("spring", "org/springframework/context/ApplicationContextInitializer", Discovery.SUBTYPE, null,
                    List.of("initialize"), "Spring context initializer"),
            new Extension("spring", "org/springframework/jdbc/core/RowMapper", Discovery.SUBTYPE, null,
                    List.of("mapRow"), "Spring JDBC callback"),

            // ---- Jackson custom (de)serializers
            new Extension("jackson", "com/fasterxml/jackson/databind/JsonDeserializer", Discovery.SUBTYPE, null,
                    List.of("deserialize"), "Jackson deserialization callback"),
            new Extension("jackson", "com/fasterxml/jackson/databind/JsonSerializer", Discovery.SUBTYPE, null,
                    List.of("serialize"), "Jackson serialization callback"),

            // ---- snakeyaml custom constructors
            new Extension("snakeyaml", "org/yaml/snakeyaml/constructor/Construct", Discovery.SUBTYPE, null,
                    List.of("construct"), "snakeyaml custom construct callback"),

            // ---- snakeyaml / JNDI style config-driven class instantiation
            new Extension("jndi", "javax/naming/Context", Discovery.SUBTYPE, null,
                    List.of("lookup"), "JNDI naming context used by lookup-style vulnerabilities")
    );

    private ExtensionPoints() {}

    public static List<Extension> forContract(String internalName) {
        List<Extension> out = new ArrayList<>();
        for (Extension e : KNOWN) if (e.contract().equals(internalName)) out.add(e);
        return out;
    }

    public static List<Extension> all() { return KNOWN; }
}
