@echo off
setlocal enableextensions
set DIR=%~dp0
set CP=%DIR%..\lib\*

rem Prefer embedded jlink runtime when available (image\bin\java.exe)
set JAVA_EXE=%DIR%java.exe
if not exist "%JAVA_EXE%" (
  set JAVA_EXE=%JAVA_HOME%\bin\java.exe
)
if not exist "%JAVA_EXE%" (
  set JAVA_EXE=java
)

rem Required for JNA on modern JDKs.
"%JAVA_EXE%" --enable-native-access=ALL-UNNAMED -cp "%CP%" network.crypta.launcher.Launcher %*
