#!/bin/bash -xe
SCRIPTPATH="$(cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P)"
CLASSPATH="$(find $SCRIPTPATH -name "*burp*.jar" -exec sh -c "echo {}: | tr -d '\n'" \;)"
java -cp "$CLASSPATH" org.springframework.boot.loader.JarLauncher $@
