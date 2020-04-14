@echo off
for /f "delims=" %%x in ('dir /od /b burp-rest-api-*.jar') do set latestjar=%%x
java -cp %latestjar%;burpsuite_pro.jar org.springframework.boot.loader.JarLauncher %*