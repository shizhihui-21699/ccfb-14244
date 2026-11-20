#!/usr/bin/env python3
"""ReachMap evaluation harness.

Runs every sample project, compares the produced verdicts against the hand-written truth in
samples/expected/*.json, and prints a precision/recall style scorecard.

The scoring is deliberately asymmetric, mirroring the tool's own priority:

  * A vulnerability the truth says is exploitable that we call UNREACHABLE is a **critical miss**
    (false negative) — this is the failure that gets applications breached.
  * A vulnerability the truth says is unreachable that we call REACHABLE with attacker input is a
    **false alarm** — the failure that makes the tool useless.
  * Calling something UNKNOWN where a definite answer is expected counts as a partial miss: it is
    honest, but it did not do its job.

Usage:
  tools/evaluate.py [--samples-dir DIR] [--keep]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT.parent / "samples"


@dataclass
class CaseResult:
    sample: str
    vuln: str
    expected: str
    actual: str
    expected_input: bool | None
    actual_input: bool
    ok: bool
    critical: bool = False
    notes: list[str] = field(default_factory=list)


def run_java(args: list[str], cp: str, main: str, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(["java", "-cp", cp, main, *args], capture_output=True, text=True, timeout=timeout)


def find_java() -> str:
    """Resolve a working JDK the same way tools/env.sh does."""
    candidates = [os.environ.get("JAVA_HOME"), "/opt/homebrew/opt/openjdk@21",
                  "/opt/homebrew/opt/openjdk@17", "/opt/homebrew/opt/openjdk"]
    for c in candidates:
        if c and Path(c, "bin", "java").exists():
            return str(Path(c, "bin", "java"))
    return "java"


def build_all() -> None:
    java = find_java()
    java_home = str(Path(java).parent.parent)
    env = dict(os.environ, JAVA_HOME=java_home, PATH=f"{java_home}/bin:" + os.environ.get("PATH", ""))
    print("== building analyzer")
    subprocess.run([str(ROOT / "tools" / "build.sh")], check=True, env=env)
    print("== building samples")
    for p in ("A", "B", "C"):
        subprocess.run([str(SAMPLES / "build-sample.sh"), p], check=True, env=env,
                       stdout=subprocess.DEVNULL)


def analyze(sample: str, out_dir: Path, extra: list[str] | None = None) -> dict:
    java = find_java()
    cp = ":".join(str(p) for p in [
        ROOT / "build" / "classes",
        ROOT / "lib" / "asm-9.7.1.jar",
        ROOT / "lib" / "asm-tree-9.7.1.jar",
        ROOT / "lib" / "asm-commons-9.7.1.jar",
        ROOT / "lib" / "asm-analysis-9.7.1.jar",
    ])
    libs = SAMPLES / "libs"
    args = ["--app", str(SAMPLES / sample / "target" / "classes")]
    for j in ("spring-web-5.3.39", "spring-context-5.3.39", "spring-beans-5.3.39",
              "spring-core-5.3.39", "spring-aop-5.3.39", "spring-expression-5.3.39",
              "log4j-api-2.14.1", "log4j-core-2.14.1", "snakeyaml-1.30",
              "commons-collections-3.2.1", "xstream-1.4.5"):
        args += ["--lib", str(libs / f"{j}.jar")]
    args += ["--vulndb", str(SAMPLES / "vulndb.json"), "--out", str(out_dir), "--name", f"sample-{sample}"]
    if extra:
        args += extra
    proc = subprocess.run([java, "-cp", cp, "dev.reachmap.Main", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        raise RuntimeError(f"analysis failed for {sample}: exit {proc.returncode}")
    return json.loads((out_dir / "reachability.json").read_text())


def explain_hits(sample: str, needle: str, out_dir: Path) -> dict:
    """Runs --explain and parses which matching nodes the analyzer could reach and how."""
    java = find_java()
    cp = ":".join(str(p) for p in [
        ROOT / "build" / "classes", ROOT / "lib" / "asm-9.7.1.jar",
        ROOT / "lib" / "asm-tree-9.7.1.jar", ROOT / "lib" / "asm-commons-9.7.1.jar",
        ROOT / "lib" / "asm-analysis-9.7.1.jar",
    ])
    libs = SAMPLES / "libs"
    args = ["--app", str(SAMPLES / sample / "target" / "classes")]
    for j in ("spring-web-5.3.39", "spring-context-5.3.39", "spring-beans-5.3.39",
              "spring-core-5.3.39", "spring-aop-5.3.39", "spring-expression-5.3.39",
              "log4j-api-2.14.1", "log4j-core-2.14.1", "snakeyaml-1.30",
              "commons-collections-3.2.1", "xstream-1.4.5"):
        args += ["--lib", str(libs / f"{j}.jar")]
    args += ["--out", str(out_dir / "explain"), "--explain", needle]
    proc = subprocess.run([java, "-cp", cp, "dev.reachmap.Main", *args], capture_output=True, text=True)
    reached, unreached = [], []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if needle not in line:
            continue
        if "-> NOT REACHED" in line:
            unreached.append(line)
        elif "-> reached in" in line:
            reached.append(line)
    return {"reached": reached, "unreached": unreached}


def path_text(finding: dict) -> str:
    parts = []
    for hop in finding.get("path", []):
        parts.append(hop.get("from", ""))
        parts.append(hop.get("to", ""))
    if finding.get("sink"):
        parts.append(finding["sink"])
    return " -> ".join(parts)


def evaluate(sample: str, report: dict) -> list[CaseResult]:
    truth = json.loads((SAMPLES / "expected" / f"{sample}.json").read_text())
    by_id = {f["id"]: f for f in report["findings"]}
    results: list[CaseResult] = []

    for exp in truth["expected"]:
        vid = exp["id"]
        want = exp["verdict"]
        want_input = exp.get("inputReachable")
        actual = by_id.get(vid, {})
        got = actual.get("verdict", "MISSING")
        got_input = bool(actual.get("inputReachable"))
        notes: list[str] = []

        ok = got == want
        # NOT_PRESENT and UNREACHABLE are both "safe" answers for an absent artifact; accept either
        # only when the expected verdict itself is one of them.
        if not ok and want == "UNREACHABLE" and got == "NOT_PRESENT":
            ok = True
            notes.append("artifact absent; NOT_PRESENT accepted for an UNREACHABLE expectation")

        if ok and want_input is not None:
            if got_input != want_input:
                ok = False
                notes.append(f"inputReachable expected {want_input}, got {got_input}")

        # Path content checks
        if ok and got in ("REACHABLE", "UNKNOWN"):
            text = path_text(actual)
            for needle in exp.get("mustMentionInPath", []):
                if needle not in text:
                    ok = False
                    notes.append(f"path missing expected symbol {needle!r}")
            for needle in exp.get("mustNotMentionInPath", []):
                if needle in text:
                    ok = False
                    notes.append(f"path wrongly mentions {needle!r}")
            route = exp.get("entryRoute")
            if route:
                actual_route = (actual.get("entry") or {}).get("route")
                if actual_route != route:
                    notes.append(f"entry route {actual_route!r} != expected {route!r} (not fatal)")

        critical = False
        # Critical miss: truth says exploitable, we say it cannot be reached.
        if want == "REACHABLE" and exp.get("inputReachable") and got == "UNREACHABLE":
            critical = True

        results.append(CaseResult(sample, vid, want, got, want_input, got_input, ok, critical, notes))

    for bad in truth.get("mustNotClaim", []):
        vid = bad["id"]
        actual = by_id.get(vid, {})
        got = actual.get("verdict")
        if got == bad["verdict"]:
            results.append(CaseResult(sample, vid, f"NOT {bad['verdict']}", got, None,
                                      bool(actual.get("inputReachable")), False, True,
                                      [bad["why"]]))

    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples-dir", default=str(SAMPLES))
    ap.add_argument("--keep", action="store_true", help="keep per-sample output directories")
    ap.add_argument("--skip-build", action="store_true")
    args = ap.parse_args()

    if not args.skip_build:
        build_all()

    all_results: list[CaseResult] = []
    out_root = Path(tempfile.mkdtemp(prefix="reachmap-eval-"))
    try:
        for sample in ("A", "B", "C"):
            print(f"\n== evaluating sample {sample}")
            report = analyze(sample, out_root / sample)
            all_results.extend(evaluate(sample, report))

            # Ordering-independent reachability assertion ("mustBeReachable" in the truth file).
            # This catches dispatch-narrowing bugs that depend on which method the worklist
            # happened to expand first.
            truth = json.loads((SAMPLES / "expected" / f"{sample}.json").read_text())
            for spec in truth.get("mustBeReachable", []):
                hits = explain_hits(sample, spec["symbol"], out_root / sample)
                ok = bool(hits["reached"]) and not hits["unreached"]
                notes = []
                if not hits["reached"]:
                    notes.append(f"{spec['symbol']} was not reachable but {spec['why']}")
                if hits["unreached"]:
                    notes.append(f"{spec['symbol']} has unreached node(s): {hits['unreached'][0]}")
                all_results.append(CaseResult(sample, spec["symbol"], "REACHED",
                                              "REACHED" if ok else "NOT REACHED",
                                              None, False, ok, False, notes))
    finally:
        if args.keep:
            print(f"\noutputs kept in {out_root}")
        else:
            shutil.rmtree(out_root, ignore_errors=True)

    print("\n" + "=" * 78)
    print(f"{'sample':6} {'vuln':16} {'expected':12} {'actual':12} {'input':6} result")
    print("-" * 78)
    for r in all_results:
        flag = "CRITICAL MISS" if r.critical else ("ok" if r.ok else "FAIL")
        print(f"{r.sample:6} {r.vuln:16} {r.expected:12} {r.actual:12} "
              f"{str(r.actual_input):6} {flag}")
        for n in r.notes:
            print(f"       - {n}")

    total = len(all_results)
    passed = sum(1 for r in all_results if r.ok)
    critical = sum(1 for r in all_results if r.critical)
    print("-" * 78)
    print(f"passed {passed}/{total}   critical misses {critical}")
    return 0 if passed == total and critical == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
