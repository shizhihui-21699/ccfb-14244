package com.acme.vulnweb.service;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decoy endpoint reachable over HTTP that calls the *safe* implementation through the shared
 * interface type. If dispatch resolution confuses the two report services, this endpoint makes
 * the mistake visible.
 */
@RestController
public class ReportController {

    private final ReportService reportService;

    public ReportController(ReportService reportService) {
        this.reportService = reportService;
    }

    @GetMapping("/plain-report")
    public String plain() {
        return reportService.render("fixed");
    }
}
