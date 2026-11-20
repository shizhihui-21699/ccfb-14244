package com.acme.vulnweb.serial;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

/**
 * Serializable session object whose readObject callback runs application logic.
 *
 * <p>The callback is only reachable if a reachable method actually deserializes untrusted bytes.
 * {@link SessionEndpoint#restore} does exactly that, so the analyzer must attach
 * {@code readObject} as a serialization callback and flag the set of deserialized types as not
 * statically enumerable.
 */
public class SessionState implements Serializable {
    private static final long serialVersionUID = 1L;

    private String user;
    private transient String restored;

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // Application logic in a deserialization callback: a prime gadget-chain foothold.
        this.restored = Migration.apply(user);
    }

    public String getRestored() { return restored; }
}
