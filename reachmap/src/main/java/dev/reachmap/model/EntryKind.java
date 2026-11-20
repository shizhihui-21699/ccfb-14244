package dev.reachmap.model;

/** Why a method was considered an entry point (attacker- or user-controlled trigger). */
public enum EntryKind {
    SPRING_CONTROLLER("HTTP endpoint (Spring MVC)"),
    JAXRS_RESOURCE("HTTP endpoint (JAX-RS)"),
    SERVLET("HTTP endpoint (Servlet)"),
    SPRING_BOOT_MAIN("Application main()"),
    MAIN_METHOD("main(String[])"),
    SPRING_SCHEDULED("Scheduled job (Spring @Scheduled)"),
    SPRING_MESSAGE_LISTENER("Message listener (JMS/AMQP/Kafka)"),
    SPRING_CONFIGURATION("Spring @Configuration/@Bean wiring (startup)"),
    SPRING_COMPONENT_INIT("Spring bean @PostConstruct / InitializingBean (startup)"),
    CLI_ARGUMENTS("Command line entry"),
    SERIALIZATION_CALLBACK("Deserialization callback (attacker-controlled stream)"),
    FRAMEWORK_CALLBACK("Framework callback (filter/listener/plugin)"),
    CUSTOM("Configured entry point"),
    STATIC_INITIALIZER("Static initializer of an entry class");

    private final String description;

    EntryKind(String description) { this.description = description; }

    public String description() { return description; }

    public String label() { return name(); }
}
