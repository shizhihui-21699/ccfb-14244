#!/usr/bin/env bash
# Runs ReachMap on an arbitrary project.
#
#   tools/run.sh --project myproject.json            # project description file
#   tools/run.sh --app target/classes --lib dep.jar --vulndb vulndb.json
#
# Any option accepted by dev.reachmap.Main can be passed through.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
source "$HERE/env.sh"

CP="$ROOT/build/classes:$ROOT/lib/asm-9.7.1.jar:$ROOT/lib/asm-tree-9.7.1.jar:$ROOT/lib/asm-commons-9.7.1.jar:$ROOT/lib/asm-analysis-9.7.1.jar"
exec "$JAVA_HOME/bin/java" -Xmx2g -cp "$CP" dev.reachmap.Main "$@"
