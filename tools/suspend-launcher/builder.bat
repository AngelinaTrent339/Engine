@echo off
setlocal

echo ====================================
echo Building suspend_launch.exe
echo ====================================
echo.

REM Try to find Visual Studio in common locations
set "VCVARSALL="

REM Try VS 2022 Insiders (Preview)
if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Preview\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARSALL=%ProgramFiles%\Microsoft Visual Studio\2022\Preview\VC\Auxiliary\Build\vcvarsall.bat"
    echo Found: Visual Studio 2022 Preview
)

REM Try VS 18 Insiders
if exist "%ProgramFiles%\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARSALL=%ProgramFiles%\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvarsall.bat"
    echo Found: Visual Studio 18 Insiders
)

REM Try VS 2022 Community
if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARSALL=%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
    echo Found: Visual Studio 2022 Community
)

REM Try VS 2022 Professional
if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARSALL=%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat"
    echo Found: Visual Studio 2022 Professional
)

REM Try VS 2022 Enterprise
if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARSALL=%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
    echo Found: Visual Studio 2022 Enterprise
)

REM Try VS 2019
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARSALL=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat"
    echo Found: Visual Studio 2019 Community
)

if "%VCVARSALL%"=="" (
    echo ERROR: Could not find Visual Studio!
    echo Please install Visual Studio 2019 or 2022
    pause
    exit /b 1
)

echo.
echo Compiling with /O2 optimization...
echo.

cmd /c ""%VCVARSALL%" x64 && cl /nologo /EHsc /W3 /O2 /DUNICODE /D_UNICODE suspend_launch.cpp /Fe:suspend_launch.exe /link psapi.lib"

set BUILD_RESULT=%ERRORLEVEL%

if %BUILD_RESULT% EQU 0 (
    echo.
    echo ====================================
    echo Build succeeded!
    echo Output: suspend_launch.exe
    echo ====================================
    echo.
    echo Usage:
    echo   suspend_launch.exe "C:\Path\RobloxPlayerBeta.exe" [options]
    echo.
    echo Options:
    echo   /nopulse  - Skip module loading (safest, no TLS execution)
    echo   /fast     - Use 1ms pulses (faster but riskier)
    echo   /rva:0xHEX - Custom TLS callback RVA
    echo.
    goto :end
)

echo.
echo ====================================
echo Build FAILED! Error code: %BUILD_RESULT%
echo ====================================
echo.
echo Troubleshooting:
echo   1. Make sure Visual Studio 2022 is installed
echo   2. Check the path to vcvarsall.bat
echo   3. Run this from VS Developer Command Prompt
echo.

:end
pause
