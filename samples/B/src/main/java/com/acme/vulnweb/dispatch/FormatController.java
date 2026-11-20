package com.acme.vulnweb.dispatch;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Endpoint that formats request input through the interface. */
@RestController
public class FormatController {

    @GetMapping("/format")
    public String format(@RequestParam("text") String text) {
        Formatter f = FormatterFactory.shared();
        return f.format(text);
    }
}
