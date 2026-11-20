package dev.reachmap.report;

import dev.reachmap.analysis.Finding;
import dev.reachmap.analysis.Uncertainty;
import dev.reachmap.analysis.Verdict;
import dev.reachmap.model.Edge;
import dev.reachmap.model.EntryPoint;
import dev.reachmap.util.Text;

import java.util.*;

/** Renders the human-facing Markdown report. English output, stable layout for diffing in CI. */
public final class MarkdownReport {

    private final ReportContext ctx;

    public MarkdownReport(ReportContext ctx) { this.ctx = ctx; }

    public String render() {
        StringBuilder sb = new StringBuilder();
        header(sb);
        summary(sb);
        actionList(sb);
        details(sb);
        uncertaintyLedger(sb);
        entryPoints(sb);
        methodology(sb);
        return sb.toString();
    }

    private void header(StringBuilder sb) {
        sb.append("# ReachMap reachability report — ").append(ctx.projectName()).append("\n\n");
        sb.append("Generated ").append(ctx.generatedAt()).append(" by reachmap ").append(ctx.toolVersion()).append(".\n\n");
        sb.append("> A vulnerability is reported **REACHABLE** only when a concrete call path from an entry ")
          .append("point exists; the path is printed as evidence. **UNREACHABLE** means no path exists *and* ")
          .append("no unanalyzable dynamic point in application code could hide one — when such a point exists, ")
          .append("the verdict is **UNKNOWN** instead. **UNKNOWN** always needs human review.\n\n");
    }

    private void summary(StringBuilder sb) {
        Map<Verdict, Integer> counts = new EnumMap<>(Verdict.class);
        for (Finding f : ctx.findings()) counts.merge(f.verdict(), 1, Integer::sum);
        sb.append("## Summary\n\n");
        sb.append("| Verdict | Count | Meaning |\n|---|---:|---|\n");
        for (Verdict v : Verdict.values()) {
            sb.append("| ").append(v.name()).append(" | ").append(counts.getOrDefault(v, 0))
              .append(" | ").append(meaning(v)).append(" |\n");
        }
        sb.append('\n');
        long reachableInput = ctx.findings().stream()
                .filter(f -> f.verdict() == Verdict.REACHABLE && f.exposedFromAttackerEntry() && f.inputReachable()).count();
        sb.append("- **").append(reachableInput).append("** reachable from attacker-controlled input (fix first)\n");
        sb.append("- **").append(ctx.findings().stream().filter(Finding::isUnreachableButOpenWorld).count())
          .append("** marked unreachable despite open-world gaps (treat with caution)\n");
        sb.append("- **").append(ctx.entries().size()).append("** entry points, **")
          .append(ctx.graphNodes()).append("** methods in graph, **").append(ctx.graphEdges()).append("** edges\n");
        sb.append("- Analysis time ").append(String.format(Locale.ROOT, "%.2fs", ctx.analysisSeconds()))
          .append(", classes indexed: ").append(ctx.classPath().allClasses().size()).append("\n\n");
    }

    private static String meaning(Verdict v) {
        return switch (v) {
            case REACHABLE -> "A proof path exists";
            case UNREACHABLE -> "No path, and closed-world audit passed";
            case UNKNOWN -> "Cannot decide — dynamic point or speculative path";
            case PATCHED -> "Present but version is outside vulnerable range";
            case NOT_PRESENT -> "Artifact not on classpath";
        };
    }

    private void actionList(StringBuilder sb) {
        List<Finding> needs = new ArrayList<>();
        for (Finding f : ctx.findings()) if (f.verdict().needsAction()) needs.add(f);
        if (needs.isEmpty()) {
            sb.append("## Findings needing action\n\n_None._\n\n");
            return;
        }
        sb.append("## Findings needing action\n\n");
        sb.append("| Severity | Vulnerability | Verdict | Confidence | Entry | Sink | Hops |\n");
        sb.append("|---|---|---|---|---|---|---:|\n");
        for (Finding f : needs) {
            sb.append("| ").append(f.severity())
              .append(" | [").append(f.vulnerabilityId()).append("](#").append(anchor(f.vulnerabilityId())).append(')')
              .append(" | **").append(f.verdict().name()).append("**")
              .append(" | ").append(f.confidence().label())
              .append(" | ").append(f.entry() == null ? "—" : md(f.entry().label()))
              .append(" | ").append(f.sink() == null ? "—" : "`" + md(f.sink().shortDisplay()) + "`")
              .append(" | ").append(f.path().size())
              .append(" |\n");
        }
        sb.append('\n');
    }

    private void details(StringBuilder sb) {
        sb.append("## Finding details\n\n");
        for (Finding f : ctx.findings()) {
            if (f.verdict() == Verdict.NOT_PRESENT || f.verdict() == Verdict.PATCHED) continue;
            sb.append("### ").append(f.vulnerabilityId()).append(" — ").append(f.title()).append("\n\n");
            sb.append("- **Verdict:** ").append(f.verdict().name())
              .append(" (confidence ").append(f.confidence().label()).append(")\n");
            sb.append("- **Artifact:** ").append(f.artifact())
              .append(f.version() != null ? " " + f.version() : "").append("\n");
            sb.append("- **Severity:** ").append(f.severity()).append("\n");
            sb.append("- **Reason:** ").append(md(f.reason())).append("\n");
            if (f.sink() != null) {
                sb.append("- **Sink:** `").append(f.sink().display()).append("`\n");
            }
            if (f.entry() != null) {
                sb.append("- **Entry:** ").append(md(f.entry().label()))
                  .append(" → `").append(f.entry().method().display()).append("`\n");
            }
            String inputText = switch (f.inputMode()) {
                case TAINTED_SINK -> "yes — attacker-controlled input traced into the vulnerable call";
                case TAINTED_ARTIFACT -> "yes — attacker-controlled input enters the vulnerable artifact "
                        + "(a parser/serializer consumes it); exploitability is plausible but the "
                        + "parser's data flow cannot be tracked further";
                case NOT_REACHED -> "no — the code is on a path from an attacker-facing entry, but "
                        + "attacker input does not reach the vulnerable call (constant / unrelated value)";
                case NOT_APPLICABLE -> "n/a — the entry is not attacker-facing (startup, scheduled or config)";
            };
            sb.append("- **Input-reachable:** ").append(inputText).append("\n\n");

            if (!f.path().isEmpty()) {
                sb.append("**Evidence path** (").append(f.path().size()).append(" hop(s)):\n\n```\n");
                EntryPoint e = f.entry();
                if (e != null) sb.append("[").append(e.kind().name()).append("] ")
                        .append(e.route() == null ? "" : e.route() + " ")
                        .append(e.method().display()).append('\n');
                else sb.append(f.path().get(0).from().display()).append('\n');
                int i = 1;
                for (Edge edge : f.path()) {
                    String line = edge.line() > 0 ? ":" + edge.line() : "";
                    String via = edge.kind().label();
                    String extra = edge.detail() != null ? "  // " + edge.detail() : "";
                    sb.append("  ").append(i++).append(". --[").append(via).append("]--> ")
                      .append(edge.to().display()).append(line).append(extra).append('\n');
                }
                sb.append("```\n\n");
                if (!f.assumptions().isEmpty()) {
                    sb.append("**Assumptions behind this path:**\n\n");
                    for (String a : f.assumptions()) sb.append("- ").append(md(a)).append('\n');
                    sb.append('\n');
                }
            }

            if (!f.blockers().isEmpty()) {
                sb.append("**Open-world blockers (why this is not a clean answer):**\n\n");
                for (Uncertainty u : f.blockers()) {
                    sb.append("- `").append(u.category().label()).append("` ").append(md(u.location()))
                      .append(" — ").append(md(u.description())).append('\n');
                }
                sb.append('\n');
            }
            if (!f.closedWorldChecks().isEmpty()) {
                sb.append("**Closed-world audit:**\n\n");
                for (String c : f.closedWorldChecks()) sb.append("- ").append(md(c)).append('\n');
                sb.append('\n');
            }
        }
        if (ctx.findings().stream().noneMatch(f -> f.verdict() != Verdict.NOT_PRESENT && f.verdict() != Verdict.PATCHED)) {
            sb.append("_No findings with a reachability verdict._\n\n");
        }
    }

    private void uncertaintyLedger(StringBuilder sb) {
        sb.append("## Uncertainty ledger\n\n");
        sb.append("Every point where the bytecode does not fully determine control flow. Entries marked ")
          .append("**app code / HIGH** are the ones that can turn an UNREACHABLE into a real vulnerability, ")
          .append("so they are listed first and are never allowed to be silently dropped.\n\n");
        List<Uncertainty> sorted = new ArrayList<>(ctx.uncertainties());
        sorted.sort(Comparator
                .comparing((Uncertainty u) -> u.inAppCode() ? 0 : 1)
                .thenComparing(u -> u.severity().ordinal())
                .thenComparing(u -> u.category().label()));
        if (sorted.isEmpty()) {
            sb.append("_None: the analyzed graph is closed and fully determined._\n\n");
            return;
        }
        sb.append("| Severity | Category | App code | Location | Description |\n|---|---|---|---|---|\n");
        for (Uncertainty u : sorted) {
            sb.append("| ").append(u.severity().name())
              .append(" | ").append(u.category().label())
              .append(" | ").append(u.inAppCode() ? "yes" : "no")
              .append(" | `").append(md(u.location())).append('`')
              .append(" | ").append(md(u.description()))
              .append(" |\n");
        }
        sb.append('\n');

        // Missing classes are called out separately: they are the strongest closed-world caveat.
        List<String> missing = new ArrayList<>(ctx.classPath().missingClasses());
        if (!missing.isEmpty()) {
            sb.append("**Classes referenced but absent from the classpath** (").append(missing.size())
              .append("). Reachability into them cannot be checked:\n\n```\n");
            int shown = 0;
            for (String m : missing) {
                if (shown++ >= 40) { sb.append("... ").append(missing.size() - 40).append(" more\n"); break; }
                sb.append(m.replace('/', '.')).append('\n');
            }
            sb.append("```\n\n");
        }
    }

    private void entryPoints(StringBuilder sb) {
        sb.append("## Entry points\n\n");
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (EntryPoint e : ctx.entries()) counts.merge(e.kind().name(), 1, Integer::sum);
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            sb.append("- **").append(e.getKey()).append("**: ").append(e.getValue()).append('\n');
        }
        sb.append('\n');
    }

    private void methodology(StringBuilder sb) {
        sb.append("## Method and known limits\n\n");
        sb.append("- **Call graph** from bytecode (ASM). Static/special/constructor calls are exact. ")
          .append("Virtual and interface calls are resolved with class-hierarchy analysis, then narrowed by the ")
          .append("set of types actually instantiated in the program (`new`, DI beans, ServiceLoader, JPA entities, ")
          .append("reflective construction) — the single largest precision lever.\n");
        sb.append("- **Dependency injection**: `@Autowired`/`@Inject` field, constructor and setter points are ")
          .append("connected to the beans that satisfy them. Ambiguous candidate sets are flagged, not guessed.\n");
        sb.append("- **Reflection**: `Class.forName`, `getMethod().invoke`, `MethodHandles`, `Class.newInstance` are ")
          .append("resolved when names are propagated constants; otherwise recorded as an open-world hole.\n");
        sb.append("- **Dynamic proxies**: `Proxy.newProxyInstance`/cglib dispatches are modelled as open callbacks to ")
          .append("reachable `InvocationHandler`s and always produce a HIGH uncertainty entry.\n");
        sb.append("- **Serialization**: `readObject`/`readResolve`/`readExternal` on reachable `Serializable` classes ")
          .append("are attached as callbacks only when a reachable method actually reads an object stream, and the ")
          .append("inability to enumerate the deserialized class set is stated explicitly.\n");
        sb.append("- **Configuration-driven dispatch**: class names found in properties/YAML/XML resources are ")
          .append("matched against the class index and become labelled edges, with the file and key recorded.\n");
        sb.append("- **Not modelled**: per-argument data flow (input reachability is entry-level only), ")
          .append("runtime values, reflection through string concatenation of unknown parts, custom class loaders, ")
          .append("and native or JNI-dispatched calls.\n");
    }

    private static String anchor(String id) {
        return id.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-");
    }

    private static String md(String s) {
        return s == null ? "" : s.replace("|", "\\|");
    }
}
