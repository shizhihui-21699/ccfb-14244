#!/usr/bin/env bash
# Convenience runner for the bundled sample projects: tools/run-sample.sh A|B|C [extra args...]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
SAMPLES="$(dirname "$ROOT")/samples"
source "$HERE/env.sh"

P="${1:?usage: run-sample.sh A|B|C [extra args]}"; shift || true
L="$SAMPLES/libs"

CP="$ROOT/build/classes:$ROOT/lib/asm-9.7.1.jar:$ROOT/lib/asm-tree-9.7.1.jar:$ROOT/lib/asm-commons-9.7.1.jar:$ROOT/lib/asm-analysis-9.7.1.jar"

ARGS=(--app "$SAMPLES/$P/target/classes")
for j in spring-web-5.3.39 spring-context-5.3.39 spring-beans-5.3.39 spring-core-5.3.39 \
         spring-aop-5.3.39 spring-expression-5.3.39 log4j-api-2.14.1 log4j-core-2.14.1 \
         snakeyaml-1.30 commons-collections-3.2.1 xstream-1.4.5; do
  ARGS+=(--lib "$L/$j.jar")
done
ARGS+=(--vulndb "$SAMPLES/vulndb.json" --out "/tmp/rm-$P" --name "sample-$P")

exec "$JAVA_HOME/bin/java" -cp "$CP" dev.reachmap.Main "${ARGS[@]}" "$@"
