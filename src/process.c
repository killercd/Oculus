#include "internal.h"
#include <stdlib.h>

typedef BOOL (WINAPI *IsWow64Process2Fn)(HANDLE, USHORT *, USHORT *);

void oculus_session_init(OculusSession *s, bool verbose) {
    ZeroMemory(s, sizeof(*s));
    s->next_hook_id = 1;
    s->verbose = verbose;
}

bool oculus_require_session(OculusSession *s, const wchar_t *operation) {
    if (!s->process) {
        oculus_set_internal_error(s, L"%ls requires an attached process; use 'open' first", operation);
        return false;
    }
    return oculus_target_alive(s);
}

bool oculus_target_alive(OculusSession *s) {
    DWORD code = 0;
    if (!GetExitCodeProcess(s->process, &code)) {
        oculus_set_error(s, GetLastError(), L"Cannot query target PID %lu", (unsigned long)s->pid);
        return false;
    }
    if (code != STILL_ACTIVE) {
        oculus_set_internal_error(s, L"Target PID %lu has exited (code %lu)",
                                  (unsigned long)s->pid, (unsigned long)code);
        return false;
    }
    return true;
}

static bool process_is_x64(OculusSession *s, HANDLE process) {
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    union { FARPROC generic; IsWow64Process2Fn typed; } proc;
    proc.generic = kernel ? GetProcAddress(kernel, "IsWow64Process2") : NULL;
    IsWow64Process2Fn fn = proc.typed;
    if (fn) {
        USHORT process_machine = 0, native_machine = 0;
        if (!fn(process, &process_machine, &native_machine)) {
            oculus_set_error(s, GetLastError(), L"IsWow64Process2 failed");
            return false;
        }
        if (process_machine != IMAGE_FILE_MACHINE_UNKNOWN || native_machine != IMAGE_FILE_MACHINE_AMD64) {
            oculus_set_internal_error(s, L"Unsupported architecture: Oculus v1 requires an x64 target");
            return false;
        }
        return true;
    }
    BOOL wow = FALSE;
    if (!IsWow64Process(process, &wow)) {
        oculus_set_error(s, GetLastError(), L"IsWow64Process failed");
        return false;
    }
    if (wow) {
        oculus_set_internal_error(s, L"Unsupported 32-bit target");
        return false;
    }
    return true;
}

static bool lookup_process_name(DWORD pid, wchar_t *name, size_t cap) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                wcsncpy(name, pe.szExeFile, cap - 1);
                name[cap - 1] = L'\0';
                found = true;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static bool prepare_target(OculusSession *s, DWORD pid, HANDLE *handle, wchar_t *name) {
    DWORD rights = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                   PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | SYNCHRONIZE;
    HANDLE h = OpenProcess(rights, FALSE, pid);
    if (!h) {
        oculus_set_error(s, GetLastError(), L"OpenProcess failed for PID %lu", (unsigned long)pid);
        return false;
    }
    if (!process_is_x64(s, h)) {
        CloseHandle(h);
        return false;
    }
    DWORD exit_code = 0;
    if (!GetExitCodeProcess(h, &exit_code) || exit_code != STILL_ACTIVE) {
        oculus_set_internal_error(s, L"PID %lu is not running", (unsigned long)pid);
        CloseHandle(h);
        return false;
    }
    if (!lookup_process_name(pid, name, MAX_PATH)) wcscpy(name, L"<unknown>");
    *handle = h;
    return true;
}

bool oculus_open_pid(OculusSession *s, uint32_t pid) {
    if (!pid) {
        oculus_set_internal_error(s, L"PID 0 is not a valid target");
        return false;
    }
    if (pid == GetCurrentProcessId()) {
        oculus_set_internal_error(s, L"Attaching Oculus to itself is unsupported");
        return false;
    }
    if (s->process) {
        oculus_set_internal_error(s, L"A process is already attached; use 'close' first");
        return false;
    }
    HANDLE h = NULL;
    wchar_t name[MAX_PATH];
    if (!prepare_target(s, (DWORD)pid, &h, name)) return false;
    s->process = h;
    s->pid = (DWORD)pid;
    s->architecture = OCULUS_ARCH_X64;
    wcscpy(s->process_name, name);
    wprintf(L"[+] Attached to %ls (PID %lu, x64)\n", name, (unsigned long)pid);
    return true;
}

bool oculus_open_name(OculusSession *s, const wchar_t *name) {
    if (s->process) {
        oculus_set_internal_error(s, L"A process is already attached; use 'close' first");
        return false;
    }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        oculus_set_error(s, GetLastError(), L"Cannot enumerate processes");
        return false;
    }
    DWORD matches[64]; size_t count = 0;
    PROCESSENTRY32W pe = {0}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0 && count < 64) matches[count++] = pe.th32ProcessID;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (!count) {
        oculus_set_internal_error(s, L"No process named '%ls' was found", name);
        return false;
    }
    if (count > 1) {
        fwprintf(stderr, L"[-] Multiple processes named '%ls'; use an explicit PID:", name);
        for (size_t i = 0; i < count; ++i) fwprintf(stderr, L" %lu", (unsigned long)matches[i]);
        fputwc(L'\n', stderr);
        return false;
    }
    return oculus_open_pid(s, matches[0]);
}

bool oculus_list_processes(OculusSession *s) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        oculus_set_error(s, GetLastError(), L"Cannot enumerate processes");
        return false;
    }
    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) {
        DWORD error = GetLastError();
        CloseHandle(snap);
        oculus_set_error(s, error, L"Process32FirstW failed");
        return false;
    }
    wprintf(L"     PID     PPID  THREADS  EXECUTABLE\n");
    size_t count = 0;
    do {
        wchar_t marker = s->process && pe.th32ProcessID == s->pid ? L'*' : L' ';
        wprintf(L"%lc %7lu  %7lu  %7lu  %ls\n", marker,
                (unsigned long)pe.th32ProcessID,
                (unsigned long)pe.th32ParentProcessID,
                (unsigned long)pe.cntThreads,
                pe.szExeFile);
        ++count;
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    wprintf(L"\n%zu process%ls listed. '*' marks the attached process.\n",
            count, count == 1 ? L"" : L"es");
    return true;
}

bool oculus_close(OculusSession *s) {
    if (!s->process) {
        oculus_set_internal_error(s, L"No process is attached");
        return false;
    }
    DWORD initial_exit = STILL_ACTIVE;
    bool was_alive = GetExitCodeProcess(s->process, &initial_exit) && initial_exit == STILL_ACTIVE;
    bool clean = true;
    while (s->hooks) {
        uint64_t id = s->hooks->id;
        if (!oculus_remove_hook(s, id)) {
            oculus_print_error(s);
            clean = false;
            break; /* Keep handle and registry: abandoning would be unsafe. */
        }
    }
    if (!clean) {
        oculus_set_internal_error(s, L"Detach refused: at least one hook could not be safely removed");
        return false;
    }
    DWORD pid = s->pid;
    CloseHandle(s->process);
    s->process = NULL; s->pid = 0; s->architecture = OCULUS_ARCH_UNKNOWN;
    s->process_name[0] = L'\0';
    if (was_alive) wprintf(L"[+] Detached from PID %lu (target is still running)\n", (unsigned long)pid);
    else wprintf(L"[+] Closed session for PID %lu (target had exited)\n", (unsigned long)pid);
    return true;
}

void oculus_print_status(const OculusSession *s) {
    if (!s->process) { puts("No process attached."); return; }
    size_t hooks = 0;
    for (const OculusHook *h = s->hooks; h; h = h->next) if (h->active) ++hooks;
    wprintf(L"PID: %lu\nProcess: %ls\nArchitecture: x64\nActive hooks: %zu\n",
            (unsigned long)s->pid, s->process_name, hooks);
}
