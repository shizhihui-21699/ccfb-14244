package com.acme.vulnlog;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Wires the audit job and runs it on a schedule.
 *
 * <p>The job is a startup/scheduled entry, so a vulnerability reached only from here must be
 * reported as reachable-but-not-attacker-input. That is exactly the kind of nuance a naive
 * scanner flattens into a false alarm.
 */
@Configuration
public class AuditConfiguration {

    @Bean
    public AuditJob auditJob() {
        return new AuditJob("${audit.template}");
    }

    @Scheduled(fixedRate = 60_000)
    public void scheduledAudit() {
        auditJob().run();
    }
}
