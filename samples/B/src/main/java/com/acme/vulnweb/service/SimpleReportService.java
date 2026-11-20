package com.acme.vulnweb.service;

import org.springframework.stereotype.Service;

/**
 * Decoy: this service is reachable from /report but never touches the vulnerable library.
 *
 * <p>If the analyzer reports the snakeyaml vulnerability as reachable through this class, it has
 * over-approximated DI bindings (two implementations of a shared supertype would be a mistake
 * here) — which is what the sample is designed to catch.
 */
@Service
public class SimpleReportService implements ReportService {

    @Override
    public String render(String id) {
        return "<html><body>report " + id + "</body></html>";
    }
}
