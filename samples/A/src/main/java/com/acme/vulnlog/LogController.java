package com.acme.vulnlog;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * A REST controller that logs a request parameter with log4j2 2.14.1.
 *
 * <p>This is the classic Log4Shell shape: the attacker-controlled string ends up in a log
 * message, and log4j2 performs message lookup substitution on it, which can reach
 * {@code JndiLookup.lookup}. Nothing in this class mentions JNDI; the path is entirely inside
 * the library.
 */
@RestController
@RequestMapping("/api")
public class LogController {

    private static final Logger LOG = LogManager.getLogger(LogController.class);

    /** Vulnerable: attacker input is logged. */
    @GetMapping("/greet")
    public String greet(@RequestParam("name") String name) {
        LOG.info("greeting {}", name);
        return "hello " + name;
    }

    /** Benign endpoint: no logging at all. */
    @GetMapping("/health")
    public String health() {
        return "ok";
    }
}
