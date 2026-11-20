#!/usr/bin/env bash
# Compiles ReachMap from source. Usage: tools/build.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
source "$HERE/env.sh"

LIB="$ROOT/lib"
OUT="$ROOT/build/classes"
mkdir -p "$OUT"

CP="$LIB/asm-9.7.1.jar:$LIB/asm-tree-9.7.1.jar:$LIB/asm-commons-9.7.1.jar:$LIB/asm-analysis-9.7.1.jar"

# Recompile everything if any source changed (cheap at this size).
find "$ROOT/src/main/java" -name '*.java' > "$ROOT/build/sources.txt"
N=$(wc -l < "$ROOT/build/sources.txt" | tr -d ' ')
echo "Compiling $N Java sources with $JAVA_HOME"
"$JAVA_HOME/bin/javac" -encoding UTF-8 --release 17 -Xlint:-options \
  -cp "$CP" -d "$OUT" @"$ROOT/build/sources.txt"
echo "OK -> $OUT"
