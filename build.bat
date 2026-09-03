@echo off
rem =============================================================================
rem  Build script for the System Informer MCP server (si-mcp.exe)
rem  Uses MSVC (cl.exe) located via vswhere. No external build system required.
rem
rem  Usage:  build.bat          -- build the server
rem          build.bat clean    -- remove build artifacts
rem =============================================================================
setlocal
set "ROOT=%~dp0"
pushd "%ROOT%"

if /I "%~1"=="clean" (
    if exist "%ROOT%build" rmdir /s /q "%ROOT%build"
    echo [build] cleaned.
    popd & exit /b 0
)

rem --- Locate Visual Studio / Build Tools with the C++ x64 toolset -------------
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSPATH="
if exist "%VSWHERE%" for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH echo [build] ERROR: Visual Studio C++ x64 toolset not found. Install "Desktop development with C++". & popd & exit /b 1

echo [build] Visual Studio: %VSPATH%
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 echo [build] ERROR: vcvars64.bat failed. & popd & exit /b 1

rem --- Locate the System Informer phnt headers --------------------------------
rem Prefer the vendored copy (self-contained repo); fall back to a sibling
rem System Informer source tree for development.
set "PHNT_INC=%ROOT%third_party\phnt\include"
if not exist "%PHNT_INC%\phnt.h" set "PHNT_INC=%ROOT%..\systeminformer-master\phnt\include"
if not exist "%PHNT_INC%\phnt.h" echo [build] ERROR: phnt headers not found (looked in third_party\phnt\include and ..\systeminformer-master\phnt\include). & popd & exit /b 1
echo [build] phnt headers: %PHNT_INC%

if not exist "%ROOT%build" mkdir "%ROOT%build"

echo [build] Compiling...
cl /nologo /W3 /O2 /MT /GS /utf-8 /std:c11 /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS /DCJSON_HIDE_SYMBOLS /DPHNT_VERSION=117 /DPHNT_MODE=1 /I "%PHNT_INC%" /I "%ROOT%third_party\cJSON" /I "%ROOT%src" "%ROOT%src\*.c" "%ROOT%third_party\cJSON\cJSON.c" /Fo"%ROOT%build\\" /Fe"%ROOT%build\si-mcp.exe" /link ntdll.lib advapi32.lib user32.lib gdi32.lib shell32.lib ole32.lib oleaut32.lib version.lib iphlpapi.lib ws2_32.lib wintrust.lib crypt32.lib psapi.lib shlwapi.lib dbghelp.lib

set "RC=%errorlevel%"
popd
if "%RC%"=="0" (echo [build] OK -- build\si-mcp.exe) else (echo [build] FAILED with exit code %RC%)
exit /b %RC%
