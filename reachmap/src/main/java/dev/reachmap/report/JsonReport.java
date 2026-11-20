package dev.reachmap.report;

import dev.reachmap.analysis.*;
import dev.reachmap.model.Edge;
import dev.reachmap.model.EdgeKind;
import dev.reachmap.model.EntryPoint;
import dev.reachmap.model.MethodId;
import dev.reachmap.util.Text;

import java.util.*;

/** Builds the machine-readable JSON report. */
public final class JsonReport {

    private final ReportContext ctx;

    public JsonReport(ReportContext ctx) { this.ctx = ctx; }

    public Map<String, Object> build() {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("tool", "reachmap");
        root.put("schemaVersion", "1.0");
        root.put("project", ctx.projectName());
        root.put("generatedAt", ctx.generatedAt());
        root.put("summary", summary());
        root.put("classpath", classpath());
        root.put("entryPoints", entryPoints());
        root.put("findings", findings());
        root.put("uncertainties", uncertainties());
        root.put("metrics", metrics());
        return root;
    }

    private Map<String, Object> summary() {
        Map<String, Object> s = new LinkedHashMap<>();
        Map<Verdict, Integer> counts = new EnumMap<>(Verdict.class);
        for (Finding f : ctx.findings()) counts.merge(f.verdict(), 1, Integer::sum);
        s.put("total", ctx.findings().size());
        for (Verdict v : Verdict.values()) s.put(v.name().toLowerCase(Locale.ROOT), counts.getOrDefault(v, 0));
        // The single most useful number: findings that need a human now.
        s.put("needsAction", (int) ctx.findings().stream().filter(f -> f.verdict().needsAction()).count());
        s.put("reachableFromAttackerInput",
                (int) ctx.findings().stream().filter(f -> f.verdict() == Verdict.REACHABLE
                        && f.exposedFromAttackerEntry() && f.inputReachable()).count());
        s.put("unreachableButOpenWorld",
                (int) ctx.findings().stream().filter(Finding::isUnreachableButOpenWorld).count());
        return s;
    }

    private Map<String, Object> classpath() {
        List<Object> roots = new ArrayList<>();
        for (var r : ctx.classPath().roots()) {
            roots.add(dev.reachmap.util.Json.map(
                    "path", r.path().toString(),
                    "source", r.source().name(),
                    "artifact", r.artifact()));
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("roots", roots);
        m.put("classesIndexed", ctx.classPath().allClasses().size());
        m.put("missingClasses", new ArrayList<>(ctx.classPath().missingClasses()));
        m.put("duplicateClasses", new ArrayList<>(ctx.classPath().duplicateClasses()));
        m.put("warnings", ctx.classPath().warnings());
        return m;
    }

    private List<Object> entryPoints() {
        List<Object> list = new ArrayList<>();
        for (EntryPoint e : ctx.entries()) {
            list.add(dev.reachmap.util.Json.map(
                    "kind", e.kind().name(),
                    "description", e.kind().description(),
                    "route", e.route(),
                    "httpMethods", e.httpMethods(),
                    "method", e.method().display(),
                    "class", e.method().displayClass(),
                    "taintedParameters", e.taintedParams(),
                    "note", e.note()));
        }
        return list;
    }

    private List<Object> findings() {
        List<Object> list = new ArrayList<>();
        for (Finding f : ctx.findings()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", f.vulnerabilityId());
            m.put("title", f.title());
            m.put("severity", f.severity());
            m.put("artifact", f.artifact());
            m.put("version", f.version());
            m.put("verdict", f.verdict().name());
            m.put("confidence", f.confidence().label());
            m.put("exposedFromAttackerEntry", f.exposedFromAttackerEntry());
            m.put("inputReachable", f.inputReachable());
            m.put("inputMode", f.inputMode().name());
            m.put("reason", f.reason());
            m.put("sink", f.sink() == null ? null : f.sink().display());
            m.put("entry", f.entry() == null ? null : entryJson(f.entry()));
            m.put("path", pathJson(f.path()));
            m.put("assumptions", f.assumptions());
            m.put("closedWorldChecks", f.closedWorldChecks());
            List<Object> blockers = new ArrayList<>();
            for (Uncertainty u : f.blockers()) blockers.add(uncertaintyJson(u));
            m.put("blockers", blockers);
            list.add(m);
        }
        return list;
    }

    private Map<String, Object> entryJson(EntryPoint e) {
        return dev.reachmap.util.Json.map(
                "kind", e.kind().name(),
                "route", e.route(),
                "httpMethods", e.httpMethods(),
                "method", e.method().display(),
                "taintedParameters", e.taintedParams());
    }

    private List<Object> pathJson(List<Edge> path) {
        List<Object> hops = new ArrayList<>();
        for (Edge e : path) {
            hops.add(dev.reachmap.util.Json.map(
                    "from", e.from().display(),
                    "to", e.to().display(),
                    "kind", e.kind().label(),
                    "confidence", e.confidence().label(),
                    "line", e.line() > 0 ? e.line() : null,
                    "detail", e.detail(),
                    "assumptions", e.assumptions()));
        }
        return hops;
    }

    private List<Object> uncertainties() {
        List<Object> list = new ArrayList<>();
        for (Uncertainty u : ctx.uncertainties()) list.add(uncertaintyJson(u));
        return list;
    }

    private Map<String, Object> uncertaintyJson(Uncertainty u) {
        return dev.reachmap.util.Json.map(
                "category", u.category().label(),
                "severity", u.severity().name(),
                "location", u.location(),
                "description", u.description(),
                "inAppCode", u.inAppCode(),
                "artifact", u.artifact());
    }

    private Map<String, Object> metrics() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("analysisSeconds", ctx.analysisSeconds());
        m.put("graphNodes", ctx.graphNodes());
        m.put("graphEdges", ctx.graphEdges());
        m.put("graphTruncatedNodes", ctx.graphTruncated());
        m.put("entries", ctx.entries().size());
        m.put("uncertainties", ctx.uncertainties().size());
        m.put("openWorldBlockers", (int) ctx.uncertainties().stream()
                .filter(u -> u.inAppCode() && u.severity() == Uncertainty.Severity.HIGH).count());
        m.put("closedWorld", ctx.classPath().missingClasses().isEmpty());
        return m;
    }
}
