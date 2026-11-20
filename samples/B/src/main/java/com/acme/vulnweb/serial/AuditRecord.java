package com.acme.vulnweb.serial;

import java.io.ObjectInputStream;
import java.io.Serializable;

/**
 * Decoy: another Serializable class with a readObject, but its callback is harmless and it is
 * never the class actually deserialized at the endpoint.
 *
 * <p>Its presence tests that callback attachment is not overly liberal: the report should show
 * the callback set as an explicit assumption, not silently treat every Serializable class as
 * attacker-reachable.
 */
public class AuditRecord implements Serializable {
    private static final long serialVersionUID = 2L;
    private String note;

    private void readObject(ObjectInputStream in) throws java.io.IOException, ClassNotFoundException {
        in.defaultReadObject();
        this.note = note == null ? "" : note.trim();
    }
}
