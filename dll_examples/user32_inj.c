
#include <windows.h>
#include <stdint.h>
#include <string.h>

/*
 * Original MessageBoxA signature:
 *
 * int WINAPI MessageBoxA(
 *     HWND hWnd,
 *     LPCSTR lpText,
 *     LPCSTR lpCaption,
 *     UINT uType
 * );
 */

typedef int (WINAPI *MessageBoxAFn)(
    HWND,
    LPCSTR,
    LPCSTR,
    UINT
);

static MessageBoxAFn original_messagebox = NULL;

/*
 * Called by Oculus after creating the trampoline.
 */
__declspec(dllexport)
DWORD WINAPI OculusSetOriginal(void *trampoline) {
    memcpy(
        &original_messagebox,
        &trampoline,
        sizeof(original_messagebox)
    );

    return 1;
}

/*
 * Replacement function for MessageBoxA.
 * Same signature and calling convention.
 */
__declspec(dllexport)
int WINAPI OculusReplacementMessageBoxA(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType
) {
    /* The replacement intentionally substitutes the original message text. */
    (void)lpText;

    OutputDebugStringA(
        "[Oculus] MessageBoxA intercepted!\n"
    );

    if (!original_messagebox) {
        return 0;
    }

    /* Forward the original arguments */
    return original_messagebox(
        hWnd,
        "FUYYYY",
        lpCaption,
        uType
    );
}

/*
 * Optional export for testing.
 */
__declspec(dllexport)
uint32_t OculusExampleValue(void) {
    return UINT32_C(0x0C01115);
}

/*
 * DLL entry point.
 */
BOOL WINAPI DllMain(
    HINSTANCE instance,
    DWORD reason,
    LPVOID reserved
) {
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);

        OutputDebugStringA(
            "[Oculus] MessageBoxA wrapper loaded\n"
        );
    }
    else if (reason == DLL_PROCESS_DETACH) {
        OutputDebugStringA(
            "[Oculus] MessageBoxA wrapper unloaded\n"
        );
    }

    return TRUE;
}
