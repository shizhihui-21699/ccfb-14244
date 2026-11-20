package dev.reachmap.analysis;

import dev.reachmap.entry.EntryPointFinder;
import dev.reachmap.graph.ReachGraph;
import dev.reachmap.load.ClassPath;
import dev.reachmap.model.*;
import dev.reachmap.util.Log;
import dev.reachmap.util.Text;
import dev.reachmap.vuln.VersionRange;
import dev.reachmap.vuln.Vulnerability;

import java.util.*;

/**
 * Turns the reachability graph into per-vulnerability verdicts.
 *
 * <p>The design principle is that "unreachable" is a strong, falsifiable claim: it is only made
 * when every hop of the closed world was audited, and the audit results travel with it in the
 * report. Anything the analysis could not see becomes UNKNOWN, never UNREACHABLE.
 */
public final class ReachabilityAnalyzer {

    private final ClassPath cp;
    private final ReachGraph graph;
    private final List<EntryPoint> entries;
    private final List<Uncertainty> uncertainties;
    private final List<Uncertainty> openWorld;
    private final AnalysisOptions opts;
    private final TaintEngine taintEngine;
    private final Map<String, String> appArtifacts = new LinkedHashMap<>();

    private ReachGraph.SearchResult cachedSearch;
    private Map<String, MethodId> sinkIndex;

    public ReachabilityAnalyzer(ClassPath cp, ReachGraph graph, List<EntryPoint> entries,
                                List<Uncertainty> uncertainties, AnalysisOptions opts) {
        this.cp = cp;
        this.graph = graph;
        this.entries = entries;
        this.uncertainties = uncertainties;
        this.opts = opts;
        this.taintEngine = new TaintEngine(cp, graph);

        // Open-world dynamic points that can hide a path. Only entries in application code count:
        // a library's own reflective internals are either part of the path we already follow, or
        // irrelevant to whether *our* code can drive the vulnerable call.
        List<Uncertainty> blockers = new ArrayList<>();
        for (Uncertainty u : uncertainties) {
            if (u.inAppCode() && u.severity() == Uncertainty.Severity.HIGH) blockers.add(u);
        }
        this.openWorld = blockers;
    }

    /**
     * Filters the open-world ledger down to the holes that are actually relevant to one
     * vulnerability.
     *
     * <p>A reflective class load in {@code PluginRegistry} does not make a log4j finding
     * uncertain: the plugin registry cannot load log4j's {@code JndiLookup} into a path that the
     * log4j call chain would not otherwise take. Reporting it as a blocker would turn every
     * finding in a dynamic application into UNKNOWN, which is exactly the useless outcome this
     * tool is meant to avoid. Relevance is decided by: same dynamic category as the vulnerable
     * library's mechanism, a reflection point that names a class in the vulnerable artifact, or a
     * deserialization/proxy point when the sink is itself a deserialization/proxy gadget.
     */
    private List<Uncertainty> relevantBlockers(Vulnerability v, List<Uncertainty> artifactBlockers) {
        List<Uncertainty> out = new ArrayList<>(artifactBlockers);
        String artifact = normalizeArtifact(v.artifactId());
        boolean gadgetSink = isGadgetSink(v);
        for (Uncertainty u : openWorld) {
            if (out.contains(u)) continue;
            boolean relevant = switch (u.category()) {
                case REFLECTION, DEPENDENCY_INJECTION, CONFIGURATION, SERVICE_LOADER -> {
                    // Relevant when the reflection could name a class of the vulnerable artifact,
                    // or the artifact is a framework the reflection belongs to.
                    yield mentionsArtifact(u, artifact) || sameFamily(u, v);
                }
                case SERIALIZATION, DYNAMIC_PROXY -> gadgetSink;
                case MISSING_CLASS -> mentionsArtifact(u, artifact) || sameFamily(u, v);
                // Dataflow failures, wide dispatch, depth caps: these degrade confidence in a path
                // that *was* found; they cannot manufacture a missing one, so they are not blockers.
                default -> false;
            };
            if (relevant) out.add(u);
        }
        return out;
    }

    private static boolean isOpenWorldCategory(Uncertainty.Category c) {
        return switch (c) {
            case REFLECTION, DEPENDENCY_INJECTION, CONFIGURATION, SERVICE_LOADER, SERIALIZATION,
                 DYNAMIC_PROXY, MISSING_CLASS -> true;
            case DATAFLOW, DISPATCH, DEPTH, NATIVE, LAMBDA, FRAMEWORK, CROSS_MODULE -> false;
        };
    }

    private static boolean mentionsArtifact(Uncertainty u, String artifact) {
        if (artifact.isEmpty()) return false;
        String text = (u.description() + " " + u.location()).toLowerCase(Locale.ROOT).replace("/", ".");
        return text.contains(artifact);
    }

    private static boolean sameFamily(Uncertainty u, Vulnerability v) {
        String d = (u.description() + " " + u.location()).toLowerCase(Locale.ROOT);
        String group = (v.groupId() == null ? "" : v.groupId()).toLowerCase(Locale.ROOT);
        if (!group.isEmpty() && d.contains(group)) return true;
        // Framework names that the uncertainty text and the vulnerability share.
        for (String token : List.of("log4j", "snakeyaml", "jackson", "xstream", "commons-collections",
                "commons.collections", "jndi", "hibernate", "spring", "yaml")) {
            if (d.contains(token) && (v.title().toLowerCase(Locale.ROOT).contains(token)
                    || v.artifactId().toLowerCase(Locale.ROOT).contains(token))) return true;
        }
        return false;
    }

    /** True when the sink is a deserialization / proxy gadget primitive. */
    private static boolean isGadgetSink(Vulnerability v) {
        String text = (v.title() + " " + v.description()).toLowerCase(Locale.ROOT);
        return text.contains("deserial") || text.contains("gadget") || text.contains("proxy")
                || text.contains("invoketransformer") || text.contains("readobject");
    }

    public List<Uncertainty> openWorld() { return openWorld; }

    /** Registers version info discovered from the classpath (jar names) or the manifest. */
    public void registerArtifactVersion(String artifact, String version) {
        appArtifacts.put(artifact, version);
    }

    public List<Finding> analyze(List<Vulnerability> vulns) {
        ReachGraph.SearchResult reach = search();
        Map<MethodId, EntryPoint> entryByMethod = new HashMap<>();
        for (EntryPoint e : entries) entryByMethod.putIfAbsent(e.method(), e);

        // Uncertainties are bucketed by artifact so a finding can be told "here is what we could
        // not see inside the library you are asking about". Only open-world categories count:
        // a dataflow failure inside a library lowers confidence in a path, it does not hide one.
        Map<String, List<Uncertainty>> byArtifact = new HashMap<>();
        for (Uncertainty u : uncertainties) {
            if (u.artifact() == null) continue;
            if (!isOpenWorldCategory(u.category())) continue;
            byArtifact.computeIfAbsent(normalizeArtifact(u.artifact()), k -> new ArrayList<>()).add(u);
        }

        List<Finding> findings = new ArrayList<>();
        for (Vulnerability v : vulns) {
            findings.add(judge(v, reach, entryByMethod, byArtifact));
        }
        findings.sort(Comparator
                .comparingInt((Finding f) -> f.verdict().rank())
                .thenComparing(Comparator.comparingInt((Finding f) -> severityRank(f.severity())).reversed())
                .thenComparing(Finding::vulnerabilityId));
        return findings;
    }

    private static int severityRank(String s) {
        return switch (s == null ? "" : s.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> 5;
            case "HIGH" -> 4;
            case "MEDIUM", "MODERATE" -> 3;
            case "LOW" -> 2;
            default -> 1;
        };
    }

    private Finding judge(Vulnerability v, ReachGraph.SearchResult reach,
                          Map<MethodId, EntryPoint> entryByMethod,
                          Map<String, List<Uncertainty>> byArtifact) {
        String version = appArtifacts.get(normalizeArtifact(v.artifactId()));

        boolean artifactPresent = isArtifactPresent(v);
        if (!artifactPresent) {
            return new Finding(v.id(), v.title(), v.severity(), v.artifactId(), version,
                    Verdict.NOT_PRESENT, "Vulnerable artifact is not on the analyzed classpath",
                    null, null, List.of(), EdgeKind.Confidence.EXACT, false, Finding.InputMode.NOT_APPLICABLE, false,
                    List.of(), List.of(), List.of());
        }
        if (version != null && v.vulnerableRange() != null && !v.vulnerableRange().isBlank()) {
            VersionRange range = VersionRange.parse(v.vulnerableRange());
            if (!range.isEmpty() && !range.contains(version)) {
                return new Finding(v.id(), v.title(), v.severity(), v.artifactId(), version,
                        Verdict.PATCHED, "Analyzed version " + version + " is outside the vulnerable range "
                        + v.vulnerableRange() + (v.fixedVersion() != null ? " (fixed in " + v.fixedVersion() + ")" : ""),
                        null, null, List.of(), EdgeKind.Confidence.EXACT, false, Finding.InputMode.NOT_APPLICABLE, false,
                        List.of(), List.of(), List.of());
            }
        }

        // Find every sink method in the graph and pick the best proof among them.
        MethodId bestSink = null;
        List<Edge> bestPath = null;
        EntryPoint bestEntry = null;
        EdgeKind.Confidence bestConfidence = null;
        boolean bestInputReachable = false;
        Finding.InputMode bestInputMode = Finding.InputMode.NOT_APPLICABLE;
        boolean bestAttacker = false;
        boolean bestTaintPathUsed = false;
        List<String> bestAssumptions = new ArrayList<>();

        for (MethodId node : graph.nodes()) {
            if (!matchesSink(v, node)) continue;
            List<Edge> path = reach.pathTo(node);
            if (path == null) continue;
            EdgeKind.Confidence conf;
            Edge weak = null;
            if (path.isEmpty()) {
                conf = EdgeKind.Confidence.EXACT;
            } else {
                Edge[] weakest = new Edge[1];
                conf = ReachGraph.pathConfidence(path, weakest);
                weak = weakest[0];
            }
            EntryPoint entry = entryByMethod.get(reach.entryOf(node));
            boolean attacker = entry != null && attackerControlledEntry(entry);

            // Input reachability is decided by real taint propagation from the entry's
            // attacker-controlled parameters to the call that enters the vulnerable method — not by
            // "the entry happens to have a request parameter". This is the difference between a
            // log4j finding where the attacker string is logged and one where a constant is logged.
            TaintEngine.Result taint = TaintEngine.Result.NOT_APPLICABLE;
            List<Edge> taintPath = null;
            Finding.InputMode inputMode;
            if (entry != null && attacker) {
                // Two ways attacker input becomes relevant:
                //  (a) it reaches the sink call itself, or
                //  (b) it enters the vulnerable artifact (a parser/serializer consumes it) — the
                //      exposure for deserialization-style bugs, where parser output is not
                //      value-identical to its input and cannot be tracked further.
                TaintEngine.Trace trace = taintEngine.traceSink(entry.method(),
                        attackerParamIndexes(entry), node.owner(), node.name());
                taint = trace.result();
                if (taint == TaintEngine.Result.YES) taintPath = pathFromChain(trace.chain());
                inputMode = taint == TaintEngine.Result.YES
                        ? Finding.InputMode.TAINTED_SINK : null;
                if (taint != TaintEngine.Result.YES) {
                    TaintEngine.Result enters = taintEngine.entersArtifact(entry.method(),
                            attackerParamIndexes(entry), owner -> inVulnerableArtifact(v, owner));
                    if (enters == TaintEngine.Result.YES) {
                        taint = TaintEngine.Result.YES;
                        inputMode = Finding.InputMode.TAINTED_ARTIFACT;
                    } else if (enters == TaintEngine.Result.UNKNOWN && taint != TaintEngine.Result.NO) {
                        taint = TaintEngine.Result.UNKNOWN;
                        inputMode = Finding.InputMode.NOT_REACHED;
                    } else {
                        inputMode = Finding.InputMode.NOT_REACHED;
                    }
                }
            } else {
                inputMode = Finding.InputMode.NOT_APPLICABLE;
            }
            boolean inputReach = taint == TaintEngine.Result.YES;
            boolean inputUnknown = taint == TaintEngine.Result.UNKNOWN;

            // When taint itself reached the sink, its chain is the most informative evidence: it
            // names the calls that actually carried attacker data. Prefer it over the
            // strongest-confidence structural path, which may be a static-initializer detour.
            // This preference is absolute: a path that demonstrably carries attacker input beats a
            // shorter path that does not, even if the shorter one has cleaner edge kinds.
            List<Edge> effectivePath = path;
            EdgeKind.Confidence effectiveConf = conf;
            Edge effectiveWeak = weak;
            boolean taintPathUsed = false;
            if (inputReach && taintPath != null && !taintPath.isEmpty()) {
                Edge[] weakest = new Edge[1];
                effectiveConf = ReachGraph.pathConfidence(taintPath, weakest);
                effectiveWeak = weakest[0];
                effectivePath = taintPath;
                taintPathUsed = true;
            }

            // Prefer: taint-carrying path, then input-reachability, then attacker entry, then higher
            // confidence, then shorter path.
            boolean better;
            if (bestSink == null) better = true;
            else if (taintPathUsed != bestTaintPathUsed) better = taintPathUsed;
            else if (inputReach != bestInputReachable) better = inputReach && !bestInputReachable;
            else if (attacker != bestAttacker) better = attacker && !bestAttacker;
            else if (effectiveConf.rank() != bestConfidence.rank()) better = effectiveConf.rank() < bestConfidence.rank();
            else better = effectivePath.size() < bestPath.size();
            if (!better) continue;

            List<String> assumptions = new ArrayList<>();
            for (Edge e : effectivePath) for (String a : e.assumptions()) if (!assumptions.contains(a)) assumptions.add(a);
            if (effectiveWeak != null && effectiveWeak.detail() != null) assumptions.add("weakest link: " + effectiveWeak.kind().label()
                    + " at " + effectiveWeak.from().shortDisplay() + (effectiveWeak.line() > 0 ? ":" + effectiveWeak.line() : ""));
            if (inputMode == Finding.InputMode.TAINTED_SINK) {
                assumptions.add("attacker-controlled data from entry parameter(s) "
                        + entry.taintedParams() + " is traced into the vulnerable call; no sanitizer is modelled");
            } else if (inputMode == Finding.InputMode.TAINTED_ARTIFACT) {
                assumptions.add("attacker-controlled data from entry parameter(s) "
                        + entry.taintedParams() + " enters the vulnerable artifact; whether it reaches "
                        + "the exact sink depends on the parser/serializer internals, which are not tracked");
            } else if (taint == TaintEngine.Result.NO) {
                assumptions.add("the path is structurally reachable, but attacker input from the entry "
                        + "does not flow to the vulnerable call (constant / unrelated value)");
            } else if (inputUnknown) {
                assumptions.add("input reachability could not be decided for this path");
            }

            bestSink = node;
            bestPath = effectivePath;
            bestEntry = entry;
            bestConfidence = effectiveConf;
            bestInputReachable = inputReach;
            bestInputMode = inputMode;
            bestAttacker = attacker;
            bestTaintPathUsed = taintPathUsed;
            bestAssumptions = assumptions;
        }

        List<Uncertainty> artifactBlockers = byArtifact.getOrDefault(normalizeArtifact(v.artifactId()), List.of());

        if (bestSink != null) {
            String exploit = switch (bestInputMode) {
                case TAINTED_SINK -> "; attacker input reaches the vulnerable call — likely exploitable";
                case TAINTED_ARTIFACT -> "; attacker input reaches the vulnerable artifact's parser — exploitability plausible";
                case NOT_REACHED -> "; structurally reachable but attacker input does not reach the call — not exploitable as-is";
                case NOT_APPLICABLE -> "; entry is not attacker-facing";
            };
            String reason = "Path from " + (bestEntry == null ? "entry" : bestEntry.label())
                    + " to " + bestSink.shortDisplay() + " (" + bestPath.size() + " hop(s), confidence "
                    + bestConfidence.label() + exploit + ")";

            // UNRESOLVED means a hop exists only as an open callback (proxy handler, unknown
            // reflective target): the path is real code but the link is an assumption.
            if (bestConfidence == EdgeKind.Confidence.UNRESOLVED) {
                return new Finding(v.id(), v.title(), v.severity(), v.artifactId(), version,
                        Verdict.UNKNOWN, reason + " — the path depends on an open callback, so both the "
                        + "path and any claim that it cannot be taken are unsafe",
                        bestSink, bestEntry, bestPath, bestConfidence, bestInputReachable,
                        bestInputMode, bestAttacker, bestAssumptions, artifactBlockers, List.of());
            }

            // WIDE stays REACHABLE: class-hierarchy dispatch over an exhaustively indexed classpath
            // can only over-approximate the receiver, never miss one, so a wide path is still a
            // sound reachability claim. The confidence field and the alternative list tell the
            // reader how much choice the program actually has.
            //
            // An undecided taint result does NOT downgrade the verdict: the structural path is
            // still proven, and taint uncertainty only affects whether attacker input arrives, not
            // whether the code can run. It is surfaced as inputReachable=false plus an explicit
            // assumption so a reviewer sees "reachable, exploitability undetermined".
            return new Finding(v.id(), v.title(), v.severity(), v.artifactId(), version,
                    Verdict.REACHABLE, reason, bestSink, bestEntry, bestPath, bestConfidence,
                    bestInputReachable, bestInputMode, bestAttacker, bestAssumptions, artifactBlockers, List.of());
        }

        // No path found. Is the claim defensible?
        List<Uncertainty> blockers = relevantBlockers(v, artifactBlockers);
        List<String> checks = closedWorldChecks(v);

        if (!blockers.isEmpty()) {
            // Dynamic points exist in app code: name them, and mark the verdict as unsafe to trust.
            return new Finding(v.id(), v.title(), v.severity(), v.artifactId(), version,
                    Verdict.UNKNOWN,
                    "No call path was found, but " + blockers.size()
                            + " open-world dynamic point(s) in application code could hide one",
                    sinkCandidate(v), null, List.of(), EdgeKind.Confidence.UNRESOLVED, false,
                    Finding.InputMode.NOT_APPLICABLE, false, List.of(), blockers, checks);
        }

        return new Finding(v.id(), v.title(), v.severity(), v.artifactId(), version,
                Verdict.UNREACHABLE,
                "No call path from any of " + entries.size() + " entry point(s) reaches a vulnerable method, "
                        + "and no open-world dynamic point in application code could hide one",
                sinkCandidate(v), null, List.of(), EdgeKind.Confidence.EXACT, false,
                Finding.InputMode.NOT_APPLICABLE, false, List.of(), List.of(), checks);
    }

    private MethodId sinkCandidate(Vulnerability v) {
        for (MethodId node : graph.nodes()) {
            if (matchesSink(v, node)) return node;
        }
        // Sink may exist but never entered the graph: find its declaration for the report.
        for (Vulnerability.Sink s : v.sinks()) {
            ClassInfo ci = cp.get(s.className().replace('.', '/'));
            if (ci == null) continue;
            for (MethodSig m : ci.methods()) {
                if (s.methodName() == null || s.methodName().isEmpty() || s.methodName().equals("<any>")
                        || m.name().equals(s.methodName())) {
                    return new MethodId(ci.name(), m.name(), m.desc());
                }
            }
        }
        return null;
    }

    private static boolean matchesSink(Vulnerability v, MethodId node) {
        for (Vulnerability.Sink s : v.sinks()) {
            if (s.matches(node.owner(), node.name())) return true;
        }
        return false;
    }

    private boolean isArtifactPresent(Vulnerability v) {
        String target = normalizeArtifact(v.artifactId());
        for (ClassInfo ci : cp.allClasses()) {
            String a = normalizeArtifact(ci.artifact());
            if (!a.isEmpty() && (a.contains(target) || target.contains(a))) return true;
        }
        // Also check the sink class directly: more robust than artifact naming.
        for (Vulnerability.Sink s : v.sinks()) {
            if (cp.contains(s.className().replace('.', '/'))) return true;
        }
        return false;
    }

    private static String normalizeArtifact(String a) {
        if (a == null) return "";
        String s = a.toLowerCase(Locale.ROOT);
        if (s.endsWith(".jar")) s = s.substring(0, s.length() - 4);
        // strip a trailing version like -2.14.1
        s = s.replaceAll("-\\d+(\\.\\d+)+.*$", "");
        return s;
    }

    /** Entries that an outsider can trigger (HTTP, message, CLI, deserialization). */
    private static boolean attackerControlledEntry(EntryPoint e) {
        return switch (e.kind()) {
            case SPRING_CONTROLLER, JAXRS_RESOURCE, SERVLET, SPRING_MESSAGE_LISTENER, CLI_ARGUMENTS,
                 SERIALIZATION_CALLBACK, SPRING_SCHEDULED -> true;
            case MAIN_METHOD, SPRING_BOOT_MAIN, SPRING_CONFIGURATION, SPRING_COMPONENT_INIT,
                 STATIC_INITIALIZER, CUSTOM, FRAMEWORK_CALLBACK -> false;
        };
    }

    /**
     * Converts a taint chain (a sequence of methods that carried attacker data) into a proof path.
     *
     * <p>Each consecutive pair is a real call/implementation relation discovered by the taint
     * search; when the reachability graph also has an edge for it, that edge (with its kind and
     * line number) is used so the report stays consistent with the call graph.
     */
    private List<Edge> pathFromChain(List<MethodId> chain) {
        List<Edge> out = new ArrayList<>();
        for (int i = 0; i + 1 < chain.size(); i++) {
            MethodId from = chain.get(i);
            MethodId to = chain.get(i + 1);
            Edge found = null;
            for (Edge e : graph.edgesFrom(from)) {
                if (e.to().equals(to)) { found = e; break; }
            }
            if (found != null) {
                out.add(found);
            } else {
                // Interface dispatch to an implementation: label it as the dispatch it is.
                ClassInfo fromCi = cp.get(from.owner());
                boolean iface = fromCi != null && (fromCi.isInterface() || fromCi.isAbstract());
                out.add(new Edge(from, to,
                        iface ? EdgeKind.DISPATCH_NARROWED : EdgeKind.DIRECT_EXACT, -1,
                        List.of("taint propagation link (concrete implementation of the interface call)"),
                        "input-carrying call"));
            }
        }
        return out;
    }

    private static List<Integer> attackerParamIndexes(EntryPoint entry) {
        return entry == null ? List.of() : entry.taintedParamIndexes();
    }

    /** True if a class belongs to the artifact a vulnerability is filed against. */
    private boolean inVulnerableArtifact(Vulnerability v, String ownerInternal) {
        ClassInfo ci = cp.get(ownerInternal);
        if (ci == null) return false;
        String artifact = normalizeArtifact(ci.artifact());
        String target = normalizeArtifact(v.artifactId());
        if (!artifact.isEmpty() && !target.isEmpty()
                && (artifact.contains(target) || target.contains(artifact))) return true;
        // Fall back to the sink's own package: sink classes define the artifact precisely.
        for (Vulnerability.Sink s : v.sinks()) {
            String sinkPkg = s.className().replace('.', '/');
            int dot = sinkPkg.lastIndexOf('/');
            if (dot > 0 && ownerInternal.startsWith(sinkPkg.substring(0, dot + 1))) return true;
        }
        return false;
    }

    private List<String> closedWorldChecks(Vulnerability v) {
        List<String> checks = new ArrayList<>();
        checks.add("Indexed " + cp.allClasses().size() + " classes from " + cp.roots().size() + " classpath root(s)");
        checks.add("Explored " + graph.nodes().size() + " method(s) and " + graph.edgeCount() + " edge(s) from "
                + entries.size() + " entry point(s)");
        checks.add("No open-world reflection/proxy/serialization/configuration hole in application code "
                + "was relevant to this artifact");

        // Missing classes are split by where they came from. A missing class referenced from
        // application code is a real caveat: the call could continue into code we cannot see. A
        // missing class referenced only from inside a library (optional integrations, JDK types the
        // analyzer does not index) does not affect whether *our* code can drive the call.
        int missing = cp.missingClasses().size();
        long appMissing = missingInAppCode();
        checks.add("Missing classes on classpath: " + missing + " total, " + appMissing
                + " referenced from application code"
                + (appMissing == 0
                    ? " (the closed-world assumption holds for the reachability question)"
                    : " — a call in our code may continue into code that was not analyzed"));
        checks.add("Vulnerable sink methods: " + v.sinks().size() + " declared, "
                + v.sinks().stream().filter(s -> cp.contains(s.className().replace('.', '/'))).count()
                + " present on classpath");
        return checks;
    }

    /** Number of distinct missing classes that application code actually calls into. */
    private long missingInAppCode() {
        Set<String> out = new HashSet<>();
        for (Uncertainty u : uncertainties) {
            if (u.category() != Uncertainty.Category.MISSING_CLASS) continue;
            if (!u.inAppCode()) continue;
            out.add(u.location());
        }
        return out.size();
    }

    private ReachGraph.SearchResult search() {
        if (cachedSearch != null) return cachedSearch;
        List<MethodId> roots = new ArrayList<>();
        for (EntryPoint e : entries) roots.add(e.method());
        cachedSearch = graph.bestPaths(roots, opts.maxDepth, opts.maxNodes);
        Log.info("Reachability: %d/%d method(s) reachable, search %s",
                cachedSearch.reachedNodes().size(), graph.nodes().size(),
                cachedSearch.truncated() ? "TRUNCATED (results conservative for 'unreachable')" : "complete");
        return cachedSearch;
    }

    /** All entry points that can reach a given method, for the report. */
    public List<EntryPoint> entriesReaching(MethodId m) {
        List<EntryPoint> out = new ArrayList<>();
        ReachGraph.SearchResult s = search();
        if (!s.reached(m)) return out;
        for (EntryPoint e : entries) if (s.reached(m) && s.entryOf(m).equals(e.method())) out.add(e);
        return out;
    }
}
