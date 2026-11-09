#include <windows.h>
#include <stdio.h>

#if defined(__GNUC__) && defined(__x86_64__)
__attribute__((dllexport, naked, noinline))
int OculusSampleAdd(int a, int b) {
    (void)a; (void)b;
    __asm__ volatile(
        "nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n"
        "nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n"
        "lea (%rcx,%rdx), %eax\n"
        "ret\n");
}
#else
__declspec(dllexport) __declspec(noinline)
int OculusSampleAdd(int a, int b) {
    volatile int result = a + b;
    return result;
}
#endif

int main(void) {
    SetConsoleOutputCP(CP_UTF8);
    HMODULE user32 = LoadLibraryW(L"user32.dll");
    printf("Oculus sample target PID %lu\n", (unsigned long)GetCurrentProcessId());
    puts("OculusSampleAdd(20, 22) is called once per second. Press Ctrl+C to exit.");
    fflush(stdout);
    for (;;) {
        printf("result=%d\n", OculusSampleAdd(20, 22));
        fflush(stdout); Sleep(1000);
    }
    if (user32) FreeLibrary(user32);
    return 0;
}

