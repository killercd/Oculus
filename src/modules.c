#include "internal.h"

static bool path_basename_equal(const wchar_t *path, const wchar_t *name) {
    const wchar_t *a = wcsrchr(path, L'\\');
    const wchar_t *b = wcsrchr(path, L'/');
    const wchar_t *base = a ? a : b;
    if (b && (!base || b > base)) base = b;
    return _wcsicmp(base ? base + 1 : path, name) == 0;
}

static bool is_path_qualified(const wchar_t *name) {
    return wcschr(name, L'\\') != NULL || wcschr(name, L'/') != NULL ||
           (name[0] && name[1] == L':');
}

static bool module_from_entry(const MODULEENTRY32W *me, OculusModule *out) {
    out->base = (uintptr_t)me->modBaseAddr;
    out->size = (size_t)me->modBaseSize;
    wcsncpy(out->name, me->szModule, MAX_PATH - 1); out->name[MAX_PATH - 1] = L'\0';
    wcsncpy(out->path, me->szExePath, 32767); out->path[32767] = L'\0';
    return true;
}

bool oculus_find_module(OculusSession *s, const wchar_t *name, OculusModule *out) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, s->pid);
    if (snap == INVALID_HANDLE_VALUE) {
        oculus_set_error(s, GetLastError(), L"Cannot enumerate modules for PID %lu", (unsigned long)s->pid);
        return false;
    }
    wchar_t full_query[32768];
    bool path_query = is_path_qualified(name);
    if (path_query && !GetFullPathNameW(name, 32768, full_query, NULL)) {
        DWORD error = GetLastError(); CloseHandle(snap);
        oculus_set_error(s, error, L"Cannot normalize module path '%ls'", name);
        return false;
    }
    MODULEENTRY32W me = {0}; me.dwSize = sizeof(me);
    size_t matches = 0; OculusModule candidate;
    if (Module32FirstW(snap, &me)) {
        do {
            bool entry_matches = path_query
                ? _wcsicmp(me.szExePath, full_query) == 0
                : (_wcsicmp(me.szModule, name) == 0 ||
                   path_basename_equal(me.szExePath, name) ||
                   _wcsicmp(me.szExePath, name) == 0);
            if (entry_matches) {
                module_from_entry(&me, &candidate); ++matches;
            }
        } while (Module32NextW(snap, &me));
    } else {
        DWORD e = GetLastError(); CloseHandle(snap);
        oculus_set_error(s, e, L"Module32FirstW failed for PID %lu", (unsigned long)s->pid);
        return false;
    }
    CloseHandle(snap);
    if (!matches) { oculus_set_internal_error(s, L"Module '%ls' is not loaded", name); return false; }
    if (matches > 1) { oculus_set_internal_error(s, L"Module name '%ls' is ambiguous; use a full path", name); return false; }
    *out = candidate; return true;
}

bool oculus_find_module_by_path(OculusSession *s, const wchar_t *path, OculusModule *out) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, s->pid);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me = {0}; me.dwSize = sizeof(me); bool found = false;
    if (Module32FirstW(snap, &me)) do {
        if (_wcsicmp(me.szExePath, path) == 0) { module_from_entry(&me, out); found = true; break; }
    } while (Module32NextW(snap, &me));
    CloseHandle(snap); return found;
}

bool oculus_list_modules(OculusSession *s) {
    if (!oculus_require_session(s, L"list dlls")) return false;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, s->pid);
    if (snap == INVALID_HANDLE_VALUE) {
        oculus_set_error(s, GetLastError(), L"Cannot enumerate modules"); return false;
    }
    MODULEENTRY32W me = {0}; me.dwSize = sizeof(me);
    if (!Module32FirstW(snap, &me)) {
        DWORD e = GetLastError(); CloseHandle(snap);
        oculus_set_error(s, e, L"Module enumeration failed"); return false;
    }
    wprintf(L"BASE ADDRESS        SIZE       MODULE                         PATH\n");
    size_t count = 0;
    do {
        wprintf(L"0x%016llX  %-10lu %-30ls %ls\n", (unsigned long long)(uintptr_t)me.modBaseAddr,
                (unsigned long)me.modBaseSize, me.szModule, me.szExePath); ++count;
    } while (Module32NextW(snap, &me));
    CloseHandle(snap);
    if (!count) { oculus_set_internal_error(s, L"No modules were returned"); return false; }
    return true;
}
