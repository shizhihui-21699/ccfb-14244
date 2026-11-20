#!/usr/bin/env bash
# Compiles one sample project against the shared dependency jars.
# Usage: build-sample.sh A|B|C
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
source "$ROOT/reachmap/tools/env.sh"

P="${1:?usage: build-sample.sh A|B|C}"
SRC="$HERE/$P/src/main/java"
RES="$HERE/$P/src/main/resources"
OUT="$HERE/$P/target/classes"
LIBS="$HERE/libs"

rm -rf "$OUT"; mkdir -p "$OUT"

CP="$LIBS/spring-web-5.3.39.jar:$LIBS/spring-context-5.3.39.jar:$LIBS/spring-beans-5.3.39.jar:$LIBS/spring-core-5.3.39.jar:$LIBS/spring-aop-5.3.39.jar:$LIBS/spring-expression-5.3.39.jar:$LIBS/log4j-api-2.14.1.jar:$LIBS/log4j-core-2.14.1.jar:$LIBS/snakeyaml-1.30.jar:$LIBS/commons-collections-3.2.1.jar:$LIBS/xstream-1.4.5.jar:$LIBS/javax.servlet-api-3.1.0.jar"

# Spring Boot annotations (@SpringBootApplication) come from spring-boot; provide the few we use
# via a tiny local stub so samples compile without the full Boot distribution.
STUB="$ROOT/reachmap/tools/stubs"
mkdir -p "$STUB/src/org/springframework/boot/autoconfigure" "$STUB/src/org/springframework/boot" \
         "$STUB/src/org/springframework/scheduling/annotation" "$STUB/classes"
cat > "$STUB/src/org/springframework/boot/SpringApplication.java" <<'EOF'
package org.springframework.boot;
public class SpringApplication { public static Object run(Class<?> c, String... a) { return null; } }
EOF
cat > "$STUB/src/org/springframework/boot/autoconfigure/SpringBootApplication.java" <<'EOF'
package org.springframework.boot.autoconfigure;
import java.lang.annotation.*;
@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
public @interface SpringBootApplication { Class<?>[] exclude() default {}; String[] scanBasePackages() default {}; }
EOF
cat > "$STUB/src/org/springframework/scheduling/annotation/Scheduled.java" <<'EOF'
package org.springframework.scheduling.annotation;
import java.lang.annotation.*;
@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
public @interface Scheduled { long fixedRate() default -1; long fixedDelay() default -1; String cron() default ""; }
EOF
"$JAVA_HOME/bin/javac" --release 17 -cp "$CP" -d "$STUB/classes" $(find "$STUB/src" -name '*.java')

find "$SRC" -name '*.java' > "$HERE/$P/target/sources.txt"
"$JAVA_HOME/bin/javac" --release 17 -g -proc:none -encoding UTF-8 \
  -cp "$CP:$STUB/classes" -d "$OUT" @"$HERE/$P/target/sources.txt"

if [ -d "$RES" ]; then cp -R "$RES/." "$OUT/"; fi
echo "built $P -> $OUT"
