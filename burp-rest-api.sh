#!/bin/bash -xe
SCRIPTPATH="$(cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P)"
CLASSPATH="$(find $SCRIPTPATH -name "*burp*.jar" -exec sh -c "echo {}: | tr -d '\n'" \;)"

JAVAVER="$(java -version 2>&1 | fgrep version)"
JAVA17ARGS=""

if [[ $JAVAVER == *'version "17'* ]]; then
    JAVA17ARGS="--add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED"
fi 

java $JAVA17ARGS -cp "$CLASSPATH" org.springframework.boot.loader.JarLauncher $@
