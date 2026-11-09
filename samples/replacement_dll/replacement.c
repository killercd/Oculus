#include <windows.h>
#include <string.h>

typedef int (*AddFunction)(int, int);
static AddFunction original_add;

__declspec(dllexport) DWORD WINAPI OculusSetOriginal(void *address) {
    memcpy(&original_add, &address, sizeof(original_add));
    return 1;
}

__declspec(dllexport) int OculusReplacementAdd(int a, int b) {
    int original = original_add ? original_add(a, b) : a + b;
    return original + 1000;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance; (void)reason; (void)reserved;
    return TRUE;
}
