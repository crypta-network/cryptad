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

REM Run Tanuki wrapper with our config and set anchorfile to a per-user path
REM (Command-line properties override wrapper.conf and handle spaces if quoted as one arg.)
"%WRAPPER_EXE%" -c "%CONF%" "wrapper.anchorfile=%LOCALAPPDATA%\Cryptad.anchor" %*
