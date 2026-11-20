package com.acme.vulnweb.serial;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

/** Endpoint that deserializes a request body — attacker controls the byte stream. */
@RestController
public class SessionEndpoint {

    @PostMapping("/session/restore")
    public String restore(@RequestBody byte[] body) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(body))) {
            Object o = in.readObject();
            return String.valueOf(o);
        }
    }
}
