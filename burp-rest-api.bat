@echo off
for /f "delims=" %%x in ('dir /od /b burp-rest-api-*.jar') do set latestjar=%%x

REM https://stackoverflow.com/questions/6359820/how-to-set-commands-output-as-a-variable-in-a-batch-file/6362922#6362922
SETLOCAL ENABLEDELAYEDEXPANSION
SET count=1
REM --version with double dashes print to stdout, in a different format than the single dash version
REM This is important, because escaping in findstr is non-trivial (to say the least...)
for /F "tokens=* USEBACKQ" %%F IN (`java --version`) DO (
    SET javaver!count!=%%F
    SET /a count=!count!+1
)

SET javaargs=

REM https://stackoverflow.com/questions/7005951/batch-file-find-if-substring-is-in-string-not-in-a-file
ECHO "%javaver1%" | findstr /C:"java 17" 1>nul

if %errorlevel%==0 (
    set javaargs=--add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED
)

java %javaargs% -cp %latestjar%;burpsuite_pro.jar org.springframework.boot.loader.JarLauncher %*
ENDLOCAL
