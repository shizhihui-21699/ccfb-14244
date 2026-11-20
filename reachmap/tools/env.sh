#!/usr/bin/env bash
# Locate a working JDK (the system /usr/bin/java on this machine is a stub).
set -euo pipefail

pick_jdk() {
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/javac" ] && "$JAVA_HOME/bin/java" -version >/dev/null 2>&1; then
    echo "$JAVA_HOME"; return 0
  fi
  for c in /opt/homebrew/opt/openjdk@21 /opt/homebrew/opt/openjdk@17 /opt/homebrew/opt/openjdk; do
    if [ -x "$c/bin/javac" ] && "$c/bin/java" -version >/dev/null 2>&1; then
      echo "$c"; return 0
    fi
  done
  for c in /Library/Java/JavaVirtualMachines/*/Contents/Home; do
    [ -e "$c" ] || continue
    if [ -x "$c/bin/javac" ] && "$c/bin/java" -version >/dev/null 2>&1; then
      echo "$c"; return 0
    fi
  done
  if command -v javac >/dev/null 2>&1 && command -v java >/dev/null 2>&1 && java -version >/dev/null 2>&1; then
    dirname "$(dirname "$(command -v javac)")"; return 0
  fi
  return 1
}

JDK_HOME="$(pick_jdk)" || { echo "No working JDK found. Set JAVA_HOME." >&2; exit 1; }
export JAVA_HOME="$JDK_HOME"
export PATH="$JAVA_HOME/bin:$PATH"
