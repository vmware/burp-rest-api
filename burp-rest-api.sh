#!/bin/bash -xe
SCRIPTPATH="$(cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P)"

JAVAVER="$(java -version 2>&1 | fgrep version)"
JAVA21ARGS=""

if [[ $JAVAVER == *'version "21'* ]]; then
    JAVA21ARGS="--add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED"
fi

# Find the plain JAR
PLAINJAR=$(find "$SCRIPTPATH/build/libs" -name "burp-rest-api-*-plain.jar" | head -n 1)

if [[ -z "$PLAINJAR" ]]; then
  echo "Could not find the plain JAR. Please run './gradlew jar' first."
  exit 1
fi

if [[ ! -f "$SCRIPTPATH/lib/burpsuite_pro.jar" ]]; then
  echo "Could not find lib/burpsuite_pro.jar. Please add the Burp Suite JAR to the lib directory."
  exit 1
fi

# Build the classpath: all dep-jars, Burp Suite JAR, and the plain JAR
unzip -o -d build/libs/dep-jars "build/libs/burp-rest-api-*.jar"
DEPDIR="$SCRIPTPATH/build/libs/dep-jars/BOOT-INF/lib"
CLASSPATH="$SCRIPTPATH/lib/burpsuite_pro.jar:$PLAINJAR"
for jar in "$DEPDIR"/*.jar; do
  CLASSPATH="$CLASSPATH:$jar"
done

java $JAVA21ARGS -cp "$CLASSPATH" com.vmware.burp.extension.BurpApplication "$@"
