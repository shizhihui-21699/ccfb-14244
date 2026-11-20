package com.acme.vulnweb.service;

import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.Yaml;

import java.io.StringReader;

/**
 * The only bean implementing {@link PaymentGateway}.
 *
 * <p>It parses the caller-supplied amount as YAML with snakeyaml 1.30, whose default
 * {@code Constructor} can instantiate arbitrary classes named in the document — the classic
 * snakeyaml deserialization RCE (CVE-2022-1471). Reaching {@code Yaml.load} is the proof;
 * reaching {@code Constructor} internals is the sink.
 */
@Service
public class StripeGateway implements PaymentGateway {

    @Override
    public String charge(String amount) {
        Yaml yaml = new Yaml();
        Object parsed = yaml.load(new StringReader(amount));
        return "charged " + parsed;
    }
}
