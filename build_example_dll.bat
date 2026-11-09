@echo off
setlocal

cd /d "%~dp0"
where gcc.exe >nul 2>nul
if errorlevel 1 (
    echo [ERROR] gcc.exe was not found. Add MinGW-w64 to PATH.
    exit /b 1
)

if not exist "build" mkdir "build"

echo [Oculus] Building the x64 example DLL with MinGW GCC...
gcc -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Wconversion ^
    -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN ^
    -shared dll_examples\example_injected_dll.c ^
    -o build\oculus_example_injected.dll

if errorlevel 1 (
    echo [ERROR] Failed to build build\oculus_example_injected.dll.
    exit /b 1
)

gcc -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Wconversion ^
    -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN ^
    -shared dll_examples\user32_inj.c ^
    -o build\user32_inj.dll

if errorlevel 1 (
    echo [ERROR] Failed to build build\user32_inj.dll.
    exit /b 1
)

echo [OK] Created: build\oculus_example_injected.dll
echo [OK] Created: build\user32_inj.dll
exit /b 0
