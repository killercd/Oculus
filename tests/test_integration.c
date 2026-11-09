#include "oculus/oculus.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t drain_pipe(HANDLE pipe, char *out, size_t cap) {
    size_t used = 0;
    while (used + 1 < cap) {
        DWORD available = 0;
        if (!PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL) || !available) break;
        DWORD want = available < cap - used - 1 ? available : (DWORD)(cap - used - 1), got = 0;
        if (!ReadFile(pipe, out + used, want, &got, NULL) || !got) break;
        used += got;
    }
    out[used] = '\0'; return used;
}

int main(int argc, char **argv) {
    if (argc != 3 && argc != 4) {
        fprintf(stderr, "usage: test_integration target.exe replacement.dll [expected-hooked-result]\n");
        return 2;
    }
    const char *expected_hooked = argc == 4 ? argv[3] : "result=1042";
    wchar_t target[MAX_PATH], dll[MAX_PATH];
    if (!MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, target, MAX_PATH) ||
        !MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, dll, MAX_PATH)) return 2;
    wchar_t target_full[32768], dll_full[32768];
    if (!GetFullPathNameW(target, 32768, target_full, NULL) ||
        !GetFullPathNameW(dll, 32768, dll_full, NULL)) return 2;

    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE}; HANDLE read_pipe = NULL, write_pipe = NULL;
    if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) return 2;
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si; PROCESS_INFORMATION pi; ZeroMemory(&si, sizeof(si)); ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = write_pipe; si.hStdError = write_pipe; si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    wchar_t command[32768]; _snwprintf(command, 32768, L"\"%ls\"", target_full);
    if (!CreateProcessW(target_full, command, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcess failed: %lu\n", (unsigned long)GetLastError());
        CloseHandle(read_pipe); CloseHandle(write_pipe); return 2;
    }
    CloseHandle(write_pipe); CloseHandle(pi.hThread); Sleep(500);
    int result = 1; OculusSession session; oculus_session_init(&session, false); uint64_t id = 0;
    if (!oculus_open_pid(&session, pi.dwProcessId)) goto cleanup;
    if (!oculus_load_library(&session, dll_full)) goto cleanup;
    if (!oculus_install_hook(&session, "OculusSampleAdd", L"oculus_sample_target.exe",
                             "OculusReplacementAdd", dll, &id)) goto cleanup;
    { char before[4096]; drain_pipe(read_pipe, before, sizeof(before)); }
    Sleep(1300);
    char hooked[4096]; drain_pipe(read_pipe, hooked, sizeof(hooked));
    if (!strstr(hooked, expected_hooked)) {
        fprintf(stderr, "hook output '%s' missing; got: %s\n", expected_hooked, hooked); goto cleanup;
    }
    if (!oculus_remove_hook(&session, id)) goto cleanup;
    Sleep(1300);
    char restored[4096]; drain_pipe(read_pipe, restored, sizeof(restored));
    if (!strstr(restored, "result=42")) { fprintf(stderr, "restore output missing; got: %s\n", restored); goto cleanup; }
    if (!oculus_close(&session)) goto cleanup;
    printf("integration test passed (42 -> %s -> 42)\n", expected_hooked + 7); result = 0;
cleanup:
    if (result && session.last_error[0]) fwprintf(stderr, L"integration failure: %ls\n", session.last_error);
    if (session.process) oculus_close(&session);
    TerminateProcess(pi.hProcess, 0); WaitForSingleObject(pi.hProcess, 3000);
    CloseHandle(pi.hProcess); CloseHandle(read_pipe); return result;
}
