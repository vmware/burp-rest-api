@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

REM Find the plain JAR
for %%x in (build\libs\burp-rest-api-*-plain.jar) do (
    set PLAINJAR=%%x
    goto :foundplain
)
:foundplain
if not defined PLAINJAR (
    echo Could not find the plain JAR. Please run 'gradlew jar' first.
    exit /b 1
)

REM Check for Burp Suite JAR
if not exist lib\burpsuite_pro.jar (
    echo Could not find lib\burpsuite_pro.jar. Please add the Burp Suite JAR to the lib directory.
    exit /b 1
)

REM Build the classpath: burpsuite_pro.jar;plainjar;all dep-jars
set CLASSPATH=lib\burpsuite_pro.jar;%PLAINJAR%
for %%j in (build\libs\dep-jars\BOOT-INF\lib\*.jar) do (
    set CLASSPATH=!CLASSPATH!;%%j
)

REM Java version check for Java > 17 options
set JAVAARGS=
for /F "tokens=2 delims=. " %%F IN ('java -version 2^>^&1 ^| findstr /C:"version"') DO (
    set JAVAMAJOR=%%F
)
if defined JAVAMAJOR if %JAVAMAJOR% GTR 17 set JAVAARGS=--add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED

java %JAVAARGS% -cp "%CLASSPATH%" com.vmware.burp.extension.BurpApplication %*
ENDLOCAL