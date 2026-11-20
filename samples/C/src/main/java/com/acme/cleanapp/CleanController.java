package com.acme.cleanapp;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Clean application: the vulnerable libraries are on the classpath but never called in a
 * dangerous way.
 *
 * <p>This is the false-positive test. A dependency scanner reports log4j-core 2.14.1,
 * commons-collections 3.2.1 and snakeyaml 1.30 here. A reachability analyzer must say
 * UNREACHABLE — and must say so for the right reason (sinks exist but no entry reaches them),
 * not because it failed to index the jars.
 */
@RestController
public class CleanController {

    private static final Logger LOG = LogManager.getLogger(CleanController.class);

    /** Logs only constant text: message lookup has nothing attacker-supplied to substitute. */
    @GetMapping("/ping")
    public String ping(@RequestParam("x") String x) {
        LOG.info("ping received");
        return "pong";
    }

    @GetMapping("/sum")
    public String sum(@RequestParam("a") int a, @RequestParam("b") int b) {
        return String.valueOf(a + b);
    }
}
