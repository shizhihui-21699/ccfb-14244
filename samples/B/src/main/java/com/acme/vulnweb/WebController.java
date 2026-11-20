package com.acme.vulnweb;

import com.acme.vulnweb.service.PaymentGateway;
import com.acme.vulnweb.service.ReportService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP surface.
 *
 * <p>{@code /pay} reaches a vulnerable library method only through an injected interface; the
 * concrete implementation is never named at the call site. {@code /report} is a decoy: the
 * service it calls does exist, but the vulnerable code it would reach is guarded off by a flag.
 */
@RestController
public class WebController {

    @Autowired
    private PaymentGateway gateway;

    @Autowired
    private ReportService reportService;

    @GetMapping("/pay")
    public String pay(@RequestParam("amount") String amount) {
        return gateway.charge(amount);
    }

    @GetMapping("/report")
    public String report(@RequestParam("id") String id) {
        return reportService.render(id);
    }
}
