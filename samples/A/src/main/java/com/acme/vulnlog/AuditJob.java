package com.acme.vulnlog;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Batch job that logs a value read from configuration.
 *
 * <p>The string is not attacker-controlled at the HTTP boundary, so this is a reachability
 * question about a startup/cron path rather than an exploit. It exists to make the report's
 * "reachable but not input-reachable" distinction testable.
 */
public class AuditJob {

    private static final Logger LOG = LogManager.getLogger(AuditJob.class);

    private final String auditTemplate;

    public AuditJob(String auditTemplate) {
        this.auditTemplate = auditTemplate;
    }

    public void run() {
        LOG.info("audit: {}", auditTemplate);
    }
}
