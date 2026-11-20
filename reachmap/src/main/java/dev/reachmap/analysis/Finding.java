package dev.reachmap.analysis;

import dev.reachmap.model.Edge;
import dev.reachmap.model.EdgeKind;
import dev.reachmap.model.MethodId;
import dev.reachmap.model.EntryPoint;

import java.util.ArrayList;
import java.util.List;

/** One vulnerability judged against the reachability graph. */
public final class Finding {
    private final String vulnerabilityId;
    private final String title;
    private final String severity;
    private final String artifact;
    private final String version;
    private final Verdict verdict;
    private final String reason;
    private final MethodId sink;
    private final EntryPoint entry;
    private final List<Edge> path;
    private final EdgeKind.Confidence confidence;
    private final boolean inputReachable;
    private final InputMode inputMode;
    private final boolean exposedFromAttackerEntry;
    private final List<String> assumptions;
    private final List<Uncertainty> blockers;
    private final List<String> closedWorldChecks;

    /** How attacker input relates to the sink. */
    public enum InputMode {
        /** Tainted data was traced into the call to the sink itself. */
        TAINTED_SINK,
        /** Tainted data entered the vulnerable artifact (parser/serializer); exploitability plausible. */
        TAINTED_ARTIFACT,
        /** An attacker-facing entry leads there, but input does not flow to the sink. */
        NOT_REACHED,
        /** The entry is not attacker-facing (startup / scheduled / config). */
        NOT_APPLICABLE
    }

    public Finding(String vulnerabilityId, String title, String severity, String artifact, String version,
                   Verdict verdict, String reason, MethodId sink, EntryPoint entry, List<Edge> path,
                   EdgeKind.Confidence confidence, boolean inputReachable, InputMode inputMode,
                   boolean exposedFromAttackerEntry,
                   List<String> assumptions, List<Uncertainty> blockers, List<String> closedWorldChecks) {
        this.vulnerabilityId = vulnerabilityId;
        this.title = title;
        this.severity = severity;
        this.artifact = artifact;
        this.version = version;
        this.verdict = verdict;
        this.reason = reason;
        this.sink = sink;
        this.entry = entry;
        this.path = path == null ? List.of() : List.copyOf(path);
        this.confidence = confidence == null ? EdgeKind.Confidence.EXACT : confidence;
        this.inputReachable = inputReachable;
        this.inputMode = inputMode == null ? InputMode.NOT_APPLICABLE : inputMode;
        this.exposedFromAttackerEntry = exposedFromAttackerEntry;
        this.assumptions = assumptions == null ? List.of() : List.copyOf(assumptions);
        this.blockers = blockers == null ? List.of() : List.copyOf(blockers);
        this.closedWorldChecks = closedWorldChecks == null ? List.of() : List.copyOf(closedWorldChecks);
    }

    public String vulnerabilityId() { return vulnerabilityId; }
    public String title() { return title; }
    public String severity() { return severity; }
    public String artifact() { return artifact; }
    public String version() { return version; }
    public Verdict verdict() { return verdict; }
    public String reason() { return reason; }
    public MethodId sink() { return sink; }
    public EntryPoint entry() { return entry; }
    public List<Edge> path() { return path; }
    public EdgeKind.Confidence confidence() { return confidence; }
    public boolean inputReachable() { return inputReachable; }
    public InputMode inputMode() { return inputMode; }
    public boolean exposedFromAttackerEntry() { return exposedFromAttackerEntry; }
    public List<String> assumptions() { return assumptions; }
    public List<Uncertainty> blockers() { return blockers; }
    public List<String> closedWorldChecks() { return closedWorldChecks; }

    /** True when the verdict is "safe" but relies on dynamic analysis gaps. */
    public boolean isUnreachableButOpenWorld() {
        return verdict == Verdict.UNREACHABLE && !blockers.isEmpty();
    }
}
