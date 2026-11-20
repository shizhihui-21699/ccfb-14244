# ReachMap

ReachMap answers one question per reported vulnerability: **can our application actually reach
the vulnerable method from an entry point an attacker can drive — and if so, exactly how?**

A weekly dependency scan tells you that log4j-core 2.14.1 is on the classpath. ReachMap tells you
that `GET /api/greet` logs a request parameter, that log4j's message substitution on that path is
the Log4Shell vector, and it prints the call path as evidence. It also tells you which findings a
bytecode-level analysis genuinely cannot decide, instead of pretending.

## Why this is not just "grep for the sink"

Naive reachability fails in two opposite ways, and both are expensive:

* **False negative (dangerous).** The vulnerable method *is* reachable, but through a hop the
  analyzer did not model — reflection, dependency injection, a dynamic proxy, a serialization
  callback, a class named in a config file. Declaring it unreachable gets the vulnerability
  ignored.
* **False positive (useless).** Everything that mentions the library is called "reachable", so the
  report is a wall of noise nobody reads.

ReachMap is built around keeping those apart. It resolves hidden call relations explicitly, and
when it cannot, it says **UNKNOWN** rather than guessing.

## Verdicts

| Verdict | Meaning |
|---|---|
| `REACHABLE` | A concrete call path from an entry point to a vulnerable method exists. The path is printed hop by hop, with edge kinds and confidence. `inputReachable` says whether attacker-controlled input demonstrably flows to the sink. |
| `UNREACHABLE` | No path exists **and** no open-world dynamic point relevant to this artifact could hide one. The closed-world checks that justify the claim are attached. |
| `UNKNOWN` | A path may exist but the analysis cannot see it (reflection with an unknown name, proxy dispatch, an unenumerated deserialization class set, or a missing dependency class in our own code). Always needs human review. |
| `PATCHED` | The artifact is present but its version is outside the vulnerable range. |
| `NOT_PRESENT` | The artifact is not on the analyzed classpath at all. |

`REACHABLE` is intentionally split by `inputReachable`: a finding that is structurally reachable
but where no attacker input reaches the sink (a constant log message, a bundled-resource parser)
is a very different ticket from an exploitable one. ReachMap reports both and labels them.

## What it models (and how)

See `docs/DESIGN.md` for the full treatment. In short:

* **Call graph** from bytecode (ASM). Static/special/constructor calls are exact. Virtual and
  interface calls use class-hierarchy analysis, then are narrowed to the types the program
  actually instantiates (from `new`, DI beans, ServiceLoader, JPA entities, reflective
  construction). Library interfaces keep their full subtype closure — a library constructs its own
  implementations through plugins and reflection, so narrowing those would drop real paths.
* **Dependency injection** — `@Autowired`/`@Inject` field, constructor and setter points connect to
  the beans that satisfy them. Ambiguous candidate sets are flagged, never silently resolved.
* **Reflection** — `Class.forName`, `getMethod().invoke`, `MethodHandles`, `newInstance` are
  resolved when the names propagate as constants; otherwise an open-world hole is recorded.
* **Dynamic proxies** — modelled as open callbacks to reachable `InvocationHandler`s, always with a
  HIGH uncertainty entry, anchored at the actual proxy-creation call site.
* **Serialization** — `readObject`/`readResolve`/`readExternal` callbacks are attached at the
  reachable `ObjectInputStream.readObject()` call site, and the inability to enumerate the
  deserialized class set is stated explicitly.
* **Configuration-driven dispatch** — class names in properties/YAML/XML resources are matched
  against the class index and become labelled edges carrying the file and key, anchored at the
  reflective load site that reads them.
* **Input reachability** — an interprocedural taint analysis over the same call graph, carrying
  attacker parameter taint through calls, containers and fields. Where taint provably stops, the
  finding is labelled input-unreachable; where parsers make data-flow opaque, exposure is judged by
  whether attacker data enters the vulnerable artifact at all.

## Build and run

Requires a JDK 17+ (the tool set `JAVA_HOME`; on this machine `/opt/homebrew/opt/openjdk@21`).
The only runtime dependency is ASM, vendored in `lib/`.

```bash
tools/build.sh                      # compile the analyzer
tools/run-sample.sh A               # run against sample project A
tools/evaluate.py                   # build samples + analyze + score against truth
```

Analyze your own project:

```bash
java -cp "build/classes:lib/asm-9.7.1.jar:lib/asm-tree-9.7.1.jar:lib/asm-commons-9.7.1.jar:lib/asm-analysis-9.7.1.jar" \
  dev.reachmap.Main \
  --app path/to/target/classes \
  --lib  path/to/dependency.jar   \  # repeat per jar
  --vulndb path/to/vulndb.json \
  --out reachmap-out/myapp \
  --name myapp
```

A Maven/Gradle classpath export (a list of jars) can be wrapped in a project file:

```json
{
  "name": "myapp",
  "app": ["target/classes"],
  "classpath": ["/abs/path/dep1.jar", "/abs/path/dep2.jar"],
  "vulndb": "vulndb.json",
  "packages": ["com.mycompany"],
  "entryMethods": ["com.mycompany.BatchMain#run"]
}
```

`java -cp ... dev.reachmap.Main --project project.json`

Options of note: `--entry-method com.acme.Foo#bar` (force an entry), `--max-targets N` (dispatch
width before an edge is downgraded to WIDE), `--no-libraries` (stop at the library boundary —
faster, but blind to deep library paths), `--verbose` (per-method taint trace), `--explain <substr>`
(print the proof path for any matching graph node — how you answer "why did it not see this hop?").

## Output

`reachability.json` (machine-readable, stable schema) and `reachability.md` (human report with, per
finding: verdict, confidence, the hop-by-hop evidence path, the assumptions behind it, and the
open-world blockers). The Markdown report also carries a full **uncertainty ledger**, sorted so that
gaps in *application* code come first — those are the ones that can turn a safe verdict into a
breach.

## Evaluation

`tools/evaluate.py` runs three sample projects and scores verdicts against hand-written truth:

* **A — Log4Shell.** An HTTP endpoint logs a request parameter into log4j 2.14.1 (must be
  REACHABLE and input-reachable), plus a benign constant-message endpoint and a scheduled job.
* **B — hidden call relations.** DI through an interface, a plugin loaded from a config file, a
  dynamic-proxy handler, and a deserialization callback — alongside decoy implementations that must
  not be conflated. Poisoned dependencies: snakeyaml 1.30 and commons-collections 3.2.1.
* **C — false-positive control.** The same vulnerable libraries present, dead code that calls a
  gadget primitive, and a parser fed only bundled data. Everything must come back not-exploitable.

The scorecard counts **critical misses** separately: a vulnerability the truth marks exploitable
that ReachMap calls UNREACHABLE. The suite passes when every case matches and there are zero
critical misses.

## Known limits

ReachMap is a static analysis, and its report is honest about where that stops mattering:

* No points-to analysis: two objects of the same static type are conflated. This can only
  over-approximate dispatch, so it never makes something falsely unreachable, but it can widen a
  path.
* Reflection whose class/name string is assembled from non-constant parts is an open-world hole.
  So are custom class loaders and JNI.
* Taint is entry-level and does not model sanitizers. "input-reachable" means attacker data
  *can* flow there, not that it is definitely exploitable.
* JDK classes are not indexed by default; calls into the JDK are treated as boundary. A missing JDK
  type does not block a verdict, but a missing class referenced from application code does.
* The proof path is the best available, not the only one. When several paths exist, the report
  prefers one that carries attacker input, then the strongest weakest-link confidence, then the
  shortest.
