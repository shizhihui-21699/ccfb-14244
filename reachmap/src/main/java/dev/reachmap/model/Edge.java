package dev.reachmap.model;

import java.util.ArrayList;
import java.util.List;

/**
 * One directed call edge in the reachability graph together with the evidence that produced it.
 *
 * <p>Every edge carries a confidence derived from its {@link EdgeKind}; path confidence is the
 * worst edge on the path, so a single speculative hop cannot masquerade as a proof.
 */
public final class Edge {
    private final MethodId from;
    private final MethodId to;
    private final EdgeKind kind;
    private final int line;             // source line in the caller, -1 if unknown
    private final List<String> assumptions;
    private final String detail;

    public Edge(MethodId from, MethodId to, EdgeKind kind, int line, List<String> assumptions, String detail) {
        this.from = from;
        this.to = to;
        this.kind = kind;
        this.line = line;
        this.assumptions = assumptions == null ? List.of() : List.copyOf(assumptions);
        this.detail = detail;
    }

    public MethodId from() { return from; }
    public MethodId to() { return to; }
    public EdgeKind kind() { return kind; }
    public int line() { return line; }
    public List<String> assumptions() { return assumptions; }
    public String detail() { return detail; }

    public EdgeKind.Confidence confidence() { return kind.baseConfidence(); }

    public Edge withTo(MethodId t, EdgeKind k) {
        return new Edge(from, t, k, line, assumptions, detail);
    }

    @Override
    public String toString() {
        return from.shortDisplay() + " -[" + kind.label() + "]-> " + to.shortDisplay()
                + (line > 0 ? " @" + line : "");
    }
}
