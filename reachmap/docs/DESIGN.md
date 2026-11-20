# ReachMap design

This document explains the modelling decisions behind the verdicts. It is written for the person
who has to trust (or challenge) a REACHABLE / UNREACHABLE claim.

## The core tension

The tool's value is the *difference* between a bytecode call graph and the calls that actually run.
Java hides those behind six mechanisms:

1. **Reflection** — `Class.forName(name).getMethod(m).invoke(obj, args)`
2. **Dependency injection** — the call site names an interface; the container decides the class
3. **Dynamic proxies** — `Proxy.newProxyInstance` dispatches into an `InvocationHandler`
4. **Serialization callbacks** — the JVM invokes `readObject` on classes the analyzer never named
5. **Configuration-driven dispatch** — a class name in a properties/YAML/XML file selects an impl
6. **Lambdas / method references / ServiceLoader** — the target is in a bootstrap argument or a
   `META-INF/services` file

Each mechanism is either *modelled* (becomes a labelled edge with a recorded assumption) or
*recorded* (becomes an uncertainty-ledger entry). Nothing is silently ignored, because a silently
ignored hop is exactly how "unreachable" becomes wrong.

## Confidence model

Every edge has a kind, and every kind a base confidence:

| Kind | Confidence | When |
|---|---|---|
| `direct` | EXACT | invokestatic / invokespecial / private / constructor |
| `dispatch-exact` | EXACT | virtual call with one possible implementation |
| `dispatch-narrowed` | NARROWED | narrowed by receiver type or the instantiated universe |
| `dispatch-wide` | WIDE | several implementations; the call may hit any |
| `di-binding` | NARROWED | the injected interface has a resolved bean |
| `di-ambiguous` | NARROWED→WIDE | several beans, qualifier/primary did not decide |
| `reflection-constant` | NARROWED | reflective target resolved from a constant |
| `reflection-configured` | NARROWED | resolved from a configuration value |
| `framework-callback` | NARROWED | the container invokes a registered implementation |
| `callback-open` | UNRESOLVED | proxy / unknown dynamic dispatch |
| `config-driven` | NARROWED | a class named in config is instantiated |

Path confidence is the **worst** edge on the path. A `REACHABLE` verdict whose weakest link is
UNRESOLVED becomes `UNKNOWN` instead, because a path built on an assumption cannot also be used to
argue the code is safe.

### Why `dispatch-wide` stays REACHABLE

Class-hierarchy dispatch over a fully indexed classpath can only *add* possible receivers, never
remove a real one. A wide edge is therefore still a sound reachability claim (the code *can* be
reached), just not a claim about which receiver. Precision is reported in the confidence field and
the "N possible implementations" assumption, and the analyzer prefers a narrower path when one
exists. Downgrading every wide edge to UNKNOWN would make any application that uses an interface
indistinguishable from an unknown.

## Precision levers

### The instantiated universe

The single biggest source of false positives in interface-heavy code is dispatching
`invokeinterface Repo.save` to every `Repo` in every jar. ReachMap intersects the subtype closure
with the set of types the program actually constructs:

* `new` instructions in reachable bytecode
* Spring/CDI beans (`@Component`, `@Bean` return types, …)
* `META-INF/services` providers
* JPA `@Entity` / `@Embeddable` types
* classes named in configuration files
* reflective construction (`Class.newInstance`, `Constructor.newInstance`)

This intersection is applied **only to application interfaces**. Library interfaces keep their full
closure, because libraries construct their own implementations through plugin systems and
reflection that the analyzer cannot enumerate — narrowing them is precisely how a tool misses
Log4Shell.

### Receiver-type narrowing

The constant/type propagator (`ConstInterpreter`) tracks the declared type of every reference on
the operand stack, not just constants. An `invokeinterface StrLookup.lookup` whose receiver slot is
declared `JndiLookup` dispatches only to `JndiLookup`. This is what turns the tail of the Log4Shell
path from "17 possible lookups" into the actual one — while still falling back to the full set when
the narrowing would leave no target (a slightly wrong local type never erases a real edge).

### Dependency injection

`DiExtractor` reads Spring and Jakarta annotations, builds a bean map, and resolves each injection
point to its candidates. For an interface call, the analyzer prefers the DI-resolved implementation
(`di-binding`) over the subtype closure. Ambiguity is recorded as `di-ambiguous` with the candidate
list — the tool does not silently pick a bean.

### Reflection

A forward dataflow tracks string and `Class` constants through the method body. When
`Class.forName("com.x.Y")` or `getMethod("m")` sees a constant name, the analyzer resolves it to the
class/method and creates a `reflection-constant` edge. When the name is not constant, the call is
recorded as an open-world hole with HIGH severity — the exact case where a false UNREACHABLE would
be dangerous.

## Taint and input reachability

Structural reachability and exploitability are separate questions with separate searches, because
the shortest structural path is often a static initializer that carries no data. The taint engine
(`TaintEngine`) propagates a per-method set of tainted parameter indices:

* tainted argument -> callee parameter (per position)
* a call over a tainted value producing a reference (or a constructor) -> tainted result — this is
  how message/event/container objects carry input forward
* reading a reference field of a tainted object yields a taint; a constructor storing a tainted
  argument taints the field

Two verdicts matter:

* **reaches the sink** — a tainted value is an argument or receiver of the call into the vulnerable
  method. This is the strongest form, and its chain is printed as evidence.
* **enters the artifact** — a tainted value enters the vulnerable library at all. For
  deserialization/parsing bugs the parser output is not value-identical to its input, so
  data-flow-through-parsers cannot be tracked soundly; but entering the parser *is* the exposure.
  A "marshalling" rule handles the common `new StringReader(input); parser.load(reader)` shape.

The distinction is what separates a log4j endpoint that logs `name` (input-reachable) from one that
logs `"ping received"` (structurally reachable, input not reachable).

## Why UNREACHABLE is a strong claim, and when it is not made

`UNREACHABLE` is only emitted when:

1. no path from any entry point reaches a sink method, **and**
2. no open-world dynamic point *relevant to this artifact* could hide one.

Relevance, not mere presence, decides (2). A reflective class load in `PluginRegistry` does not
make a log4j finding uncertain; a reflective load that could name a class in the vulnerable
artifact does. Without this filter, any dynamic application turns every finding UNKNOWN, which is
the useless outcome the tool exists to avoid.

Missing classes are split the same way. A missing class referenced from *application* code is a
real caveat (the call could continue into code we did not analyze); a missing class referenced only
inside a library (optional integrations, JDK types not indexed) does not affect whether our code can
drive the call. The report states both counts.

## Deliberate non-features

* **No sanitizer modelling.** The tool says "input reaches here", not "this is exploitable".
  Recognising validation code reliably is a research problem; claiming exploitability from a static
  tool would be dishonest.
* **No points-to analysis.** Object identity is approximated by static type. This can only widen
  dispatch (never narrow a real path), so it is sound for the reachability question; it is stated in
  the limits.
* **No interprocedural field taint across objects.** Fields are keyed by `Class#name`, which
  over-approximates (two instances of a class share field taint). Again, over-approximation in the
  "is input reachable" direction is the safe direction for not missing exploits, and the report
  labels the assumption.

## Report structure

`reachability.json` is stable and intended for CI. `reachability.md` is for humans:

1. Summary counts by verdict, with the count reachable-from-attacker-input at the top.
2. Findings needing action, sorted by verdict then severity.
3. Per-finding detail: verdict, confidence, reason, sink, entry, the hop-by-hop path with edge
   kinds and line numbers, the assumptions behind the path, and the open-world blockers.
4. The uncertainty ledger, application-code gaps first.
5. Entry points and methodology.
