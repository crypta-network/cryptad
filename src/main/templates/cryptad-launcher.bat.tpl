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

"%JAVA_EXE%" -cp "%CP%" network.crypta.launcher.LauncherKt %*

