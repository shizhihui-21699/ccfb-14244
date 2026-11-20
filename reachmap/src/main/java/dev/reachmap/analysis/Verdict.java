package dev.reachmap.analysis;

import java.util.List;

/** Final verdict for one vulnerability in one project. */
public enum Verdict {
    /** A concrete path from an entry point to a vulnerable method exists. */
    REACHABLE,
    /** No path exists, and the closed-world assumptions that make this claim are listed. */
    UNREACHABLE,
    /** A path may exist but the analysis cannot see it (dynamic dispatch, missing class, ...). */
    UNKNOWN,
    /** The vulnerable artifact is not on the analyzed classpath at all. */
    NOT_PRESENT,
    /** The artifact is present but its version is outside the vulnerable range. */
    PATCHED;

    public String label() { return name(); }

    public boolean needsAction() { return this == REACHABLE || this == UNKNOWN; }

    /** Ordered by how much attention the finding deserves. */
    public int rank() {
        return switch (this) {
            case REACHABLE -> 0;
            case UNKNOWN -> 1;
            case PATCHED -> 2;
            case UNREACHABLE -> 3;
            case NOT_PRESENT -> 4;
        };
    }
}
