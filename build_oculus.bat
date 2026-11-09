@echo off
setlocal

cd /d "%~dp0"
where gcc.exe >nul 2>nul
if errorlevel 1 (
    echo [ERROR] gcc.exe was not found. Add MinGW-w64 to PATH.
    exit /b 1
)

if not exist "build" mkdir "build"

echo [Oculus] Building with MinGW GCC...
gcc -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Wconversion ^
    -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN ^
    -Iinclude -Isrc ^
    src\errors.c src\process.c src\modules.c src\pe_exports.c ^
    src\injection.c src\x64_decode.c src\hook.c src\repl.c src\main.c ^
    -o build\oculus.exe

if errorlevel 1 (
    echo [ERROR] Oculus build failed.
    exit /b 1
)

echo [OK] Created: build\oculus.exe
exit /b 0
