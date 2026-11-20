# Sample projects

Three small Spring-flavoured Java applications compiled against vintage dependency jars that
carry known CVEs. They exist to test ReachMap against cases where the *right* answer is hard.

| Project | Shape | Tests |
|---|---|---|
| `A` | REST endpoint logs a request parameter into log4j 2.14.1 | The flagship false-negative case: Log4Shell reachable through library internals, plus a benign constant-message endpoint and a scheduled job that is reachable-but-not-input-reachable. |
| `B` | DI interface, config-selected plugin, dynamic proxy, deserialization callback; snakeyaml 1.30 + commons-collections 3.2.1 | Every hidden call relation, plus decoy implementations that must not be conflated. |
| `C` | Same vulnerable jars present; dead code calls a gadget; a parser is fed only bundled data | The false-positive control: nothing must come back exploitable. |

`vulndb.json` holds the vulnerability records (sinks + version ranges). `expected/*.json` is the
hand-written truth used by `reachmap/tools/evaluate.py`.

## Build and run

```bash
samples/fetch-libs.sh                 # one-time: download the jars into samples/libs
samples/build-sample.sh A             # compile one sample (also: tools/build.sh for ReachMap)
reachmap/tools/run-sample.sh A        # analyze it (build ReachMap first)
reachmap/tools/evaluate.py            # build + analyze + score all three against truth
```

The sample build uses tiny local stubs for three Spring Boot annotations
(`reachmap/tools/stubs/`) so the samples compile without the full Boot distribution. The analyzer
never sees the stubs — only the compiled sample and the real dependency jars.
