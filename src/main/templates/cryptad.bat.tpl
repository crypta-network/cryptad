@echo off
setlocal enableextensions
REM Resolve installation root (.. from bin)
set "SCRIPT_DIR=%~dp0"
set "ROOT_DIR=%SCRIPT_DIR%.."
set "BIN_DIR=%ROOT_DIR%\bin"
set "CONF_DIR=%ROOT_DIR%\conf"
set "LIB_DIR=%ROOT_DIR%\lib"

set "CONF=%CONF_DIR%\wrapper.conf"
if not exist "%CONF%" (
  echo Missing configuration at "%CONF%" 1>&2
  exit /b 1
)

REM Use bundled runtime when running from a jpackage app image
set "JPACKAGE_RUNTIME=%ROOT_DIR%\..\..\runtime"
if exist "%JPACKAGE_RUNTIME%\bin\java.exe" (
  if not defined JAVA_HOME (
    for %%I in ("%JPACKAGE_RUNTIME%") do set "JAVA_HOME=%%~fI"
  ) else (
    if not exist "%JAVA_HOME%\bin\java.exe" (
      for %%I in ("%JPACKAGE_RUNTIME%") do set "JAVA_HOME=%%~fI"
    )
  )
)

if defined JAVA_HOME (
  if exist "%JAVA_HOME%\bin\java.exe" (
    set "PATH=%JAVA_HOME%\bin;%PATH%"
  )
)

REM Detect architecture (normalize to amd64/arm64)
set "ARCH=%PROCESSOR_ARCHITECTURE%"
if /I "%ARCH%"=="AMD64" set "ARCH=amd64"
if /I "%ARCH%"=="ARM64" set "ARCH=arm64"
REM Wow64 case: 32-bit process on 64-bit OS
if /I "%ARCH%"=="x86" (
  if /I "%PROCESSOR_ARCHITEW6432%"=="AMD64" set "ARCH=amd64"
  if /I "%PROCESSOR_ARCHITEW6432%"=="ARM64" set "ARCH=arm64"
)

REM Prefer arch-specific wrapper exe; fallback to wrapper.exe if present
set "WRAPPER_EXE="
if /I "%ARCH%"=="amd64" set "WRAPPER_EXE=%BIN_DIR%\wrapper-windows-x86-64.exe"
if /I "%ARCH%"=="arm64" set "WRAPPER_EXE=%BIN_DIR%\wrapper-windows-arm-64.exe"
if not exist "%WRAPPER_EXE%" set "WRAPPER_EXE=%BIN_DIR%\wrapper.exe"
if not exist "%WRAPPER_EXE%" (
  echo No Windows native wrapper found in "%BIN_DIR%" for arch %ARCH% 1>&2
  exit /b 1
)

REM Native DLLs are placed directly in lib as:
REM  - wrapper-windows-x86-64.dll
REM  - wrapper-windows-arm-64.dll
REM They are resolved via wrapper.java.library.path=lib in wrapper.conf.

REM Optional: enable Java remote debugging when requested via environment.
REM When CRYPTAD_REMOTE_DEBUG is set (to any value), we append a JDWP agent option
REM using Wrapper command-line properties so it applies only for this run.
REM Tuning via env (all optional):
REM   CRYPTAD_DEBUG_PORT     default: 5005
REM   CRYPTAD_DEBUG_HOST     default: 127.0.0.1  (use '*' to listen on all interfaces)
REM   CRYPTAD_DEBUG_SUSPEND  default: n         (use 'y' to wait for debugger)
REM   CRYPTAD_DEBUG_TIMEOUT  default: unset     (milliseconds; optional)
set "WRAPPER_ANCHOR=wrapper.anchorfile=%LOCALAPPDATA%\Cryptad.anchor"
if not defined CRYPTAD_REMOTE_DEBUG goto run_wrapper

set "DEBUG_HOST=%CRYPTAD_DEBUG_HOST%"
if not defined DEBUG_HOST set "DEBUG_HOST=127.0.0.1"
set "DEBUG_PORT=%CRYPTAD_DEBUG_PORT%"
if not defined DEBUG_PORT set "DEBUG_PORT=5005"
set "DEBUG_SUSPEND=%CRYPTAD_DEBUG_SUSPEND%"
if not defined DEBUG_SUSPEND set "DEBUG_SUSPEND=n"
set "JDWP_OPT=-agentlib:jdwp=transport=dt_socket,server=y,suspend=%DEBUG_SUSPEND%,address=%DEBUG_HOST%:%DEBUG_PORT%"
if defined CRYPTAD_DEBUG_TIMEOUT set "JDWP_OPT=%JDWP_OPT%,timeout=%CRYPTAD_DEBUG_TIMEOUT%"

REM Run Tanuki wrapper with our config and set anchorfile to a per-user path.
REM Command-line properties override wrapper.conf and handle spaces if quoted as one arg.
"%WRAPPER_EXE%" -c "%CONF%" "%WRAPPER_ANCHOR%" "wrapper.ignore_sequence_gaps=TRUE" "wrapper.java.additional.250=%JDWP_OPT% " "wrapper.java.additional.251=-Xdebug" %*
goto :eof

:run_wrapper
"%WRAPPER_EXE%" -c "%CONF%" "%WRAPPER_ANCHOR%" %*
