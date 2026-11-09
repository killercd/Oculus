# Example injectable DLL

`example_injected_dll.c` is a self-contained x64 Windows DLL requiring only the
Win32 API and C runtime. Build it from the repository root with:

```bat
build_example_dll.bat
```

The output is `build\oculus_example_injected.dll`.

Start `build\oculus_sample_target.exe`, attach Oculus to its PID, and load the
DLL using an absolute path:

```text
load "C:\absolute\path\to\Oculus\build\oculus_example_injected.dll"
list functions:oculus_example_injected.dll
```

The DLL can also replace the deterministic function in the sample target:

```text
hook OculusSampleAdd:oculus_sample_target.exe OculusReplacementAdd:oculus_example_injected.dll
```

While hooked, the target result changes from `42` to `2042`. `unhook 1`
restores it to `42`. The replacement exports the optional
`OculusSetOriginal(void *)` contract, through which Oculus supplies the original
function trampoline.

This example is intentionally minimal. `DllMain` does not allocate memory,
start threads, load dependencies, or perform blocking work under the Windows
loader lock.

