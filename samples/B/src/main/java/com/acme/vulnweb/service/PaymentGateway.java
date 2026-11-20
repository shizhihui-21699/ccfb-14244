package com.acme.vulnweb.service;

/** Injected interface; the concrete bean is chosen by Spring, not by the call site. */
public interface PaymentGateway {
    String charge(String amount);
}
