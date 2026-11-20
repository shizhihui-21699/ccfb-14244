#!/usr/bin/env bash
# Downloads the third-party jars the sample projects are analyzed against.
#
# These are genuine, publicly available releases chosen because they carry well-known
# vulnerabilities (log4j-core 2.14.1 / CVE-2021-44228, snakeyaml 1.30 / CVE-2022-1471,
# commons-collections 3.2.1 / CVE-2015-6420) plus the Spring 5.3 line they are compiled against.
# Nothing here is executed; the jars are read as bytecode input only.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$HERE/libs"
mkdir -p "$DEST"
M=https://repo1.maven.org/maven2

fetch() { # group/artifact/version/file
  local path="$1" file
  file="$(basename "$path")"
  [ -f "$DEST/$file" ] && { echo "have $file"; return; }
  echo "get  $file"
  curl -sSL -o "$DEST/$file" "$M/$path"
}

fetch org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar
fetch org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar
fetch commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar
fetch org/yaml/snakeyaml/1.30/snakeyaml-1.30.jar
fetch com/thoughtworks/xstream/xstream/1.4.5/xstream-1.4.5.jar
fetch org/springframework/spring-web/5.3.39/spring-web-5.3.39.jar
fetch org/springframework/spring-context/5.3.39/spring-context-5.3.39.jar
fetch org/springframework/spring-beans/5.3.39/spring-beans-5.3.39.jar
fetch org/springframework/spring-core/5.3.39/spring-core-5.3.39.jar
fetch org/springframework/spring-aop/5.3.39/spring-aop-5.3.39.jar
fetch org/springframework/spring-expression/5.3.39/spring-expression-5.3.39.jar
fetch javax/servlet/javax.servlet-api/3.1.0/javax.servlet-api-3.1.0.jar
echo "done -> $DEST"
