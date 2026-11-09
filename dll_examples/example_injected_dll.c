/*
 * Example DLL for Oculus.
 *
 * It can be loaded with:
 *   load "C:\absolute\path\build\oculus_example_injected.dll"
 *
 * Against oculus_sample_target.exe it can also be used as a hook replacement:
 *   hook OculusSampleAdd:oculus_sample_target.exe OculusReplacementAdd:oculus_example_injected.dll
 */
#include <windows.h>
#include <stdint.h>
#include <string.h>

typedef int (*OculusSampleAddFn)(int, int);
static OculusSampleAddFn original_add;

/*
 * Oculus calls this optional convention after creating the trampoline.
 * memcpy avoids a non-portable direct cast between data and function pointers.
 */
__declspec(dllexport) DWORD WINAPI OculusSetOriginal(void *trampoline) {
    memcpy(&original_add, &trampoline, sizeof(original_add));
    return 1;
}

/* Same signature and Windows x64 ABI as the sample target export. */
__declspec(dllexport) int OculusReplacementAdd(int a, int b) {
    int value = original_add ? original_add(a, b) : a + b;
    return value + 2000;
}

/* A simple export useful when inspecting the DLL with list functions. */
__declspec(dllexport) uint32_t OculusExampleValue(void) {
    return UINT32_C(0x0C01115);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        OutputDebugStringW(L"Oculus example DLL loaded\n");
    } else if (reason == DLL_PROCESS_DETACH) {
        OutputDebugStringW(L"Oculus example DLL detached\n");
    }
    return TRUE;
}

