#include "internal.h"
#include <stdlib.h>

static bool validate_dll(OculusSession *s, const wchar_t *path) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        oculus_set_error(s, GetLastError(), L"Cannot open DLL '%ls'", path); return false;
    }
    IMAGE_DOS_HEADER dos; DWORD got = 0; bool ok = false;
    if (!ReadFile(file, &dos, sizeof(dos), &got, NULL) || got != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) {
        oculus_set_internal_error(s, L"'%ls' is not a valid PE file", path); goto done;
    }
    LARGE_INTEGER pos; pos.QuadPart = dos.e_lfanew;
    if (!SetFilePointerEx(file, pos, NULL, FILE_BEGIN)) {
        oculus_set_error(s, GetLastError(), L"Cannot seek in DLL '%ls'", path); goto done;
    }
    DWORD signature; IMAGE_FILE_HEADER header;
    if (!ReadFile(file, &signature, sizeof(signature), &got, NULL) || got != sizeof(signature) ||
        !ReadFile(file, &header, sizeof(header), &got, NULL) || got != sizeof(header) ||
        signature != IMAGE_NT_SIGNATURE) {
        oculus_set_internal_error(s, L"'%ls' has an invalid PE header", path); goto done;
    }
    if (header.Machine != IMAGE_FILE_MACHINE_AMD64 || !(header.Characteristics & IMAGE_FILE_DLL)) {
        oculus_set_internal_error(s, L"'%ls' must be an x64 PE DLL", path); goto done;
    }
    ok = true;
done:
    CloseHandle(file); return ok;
}

bool oculus_load_library(OculusSession *s, const wchar_t *input_path) {
    if (!oculus_require_session(s, L"load")) return false;
    DWORD need = GetFullPathNameW(input_path, 0, NULL, NULL);
    if (!need) { oculus_set_error(s, GetLastError(), L"Cannot normalize DLL path"); return false; }
    wchar_t *path = (wchar_t *)malloc((size_t)need * sizeof(wchar_t));
    if (!path) { oculus_set_internal_error(s, L"Out of memory"); return false; }
    if (!GetFullPathNameW(input_path, need, path, NULL) || !validate_dll(s, path)) { free(path); return false; }
    OculusModule existing;
    if (oculus_find_module_by_path(s, path, &existing)) {
        oculus_set_internal_error(s, L"DLL is already loaded at 0x%llX", (unsigned long long)existing.base);
        free(path); return false;
    }
    OculusResolvedExport loader;
    if (!oculus_resolve_export(s, L"kernel32.dll", "LoadLibraryW", &loader)) { free(path); return false; }
    SIZE_T bytes = ((SIZE_T)wcslen(path) + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(s->process, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { oculus_set_error(s, GetLastError(), L"VirtualAllocEx for DLL path failed"); free(path); return false; }
    bool ok = false; HANDLE thread = NULL; SIZE_T written = 0;
    if (!WriteProcessMemory(s->process, remote, path, bytes, &written) || written != bytes) {
        oculus_set_error(s, GetLastError(), L"Cannot write DLL path into target"); goto cleanup;
    }
    thread = CreateRemoteThread(s->process, NULL, 0,
              (LPTHREAD_START_ROUTINE)(uintptr_t)loader.address, remote, 0, NULL);
    if (!thread) { oculus_set_error(s, GetLastError(), L"CreateRemoteThread(LoadLibraryW) failed"); goto cleanup; }
    DWORD wait = WaitForSingleObject(thread, 30000);
    if (wait != WAIT_OBJECT_0) {
        if (wait == WAIT_TIMEOUT)
            oculus_set_internal_error(s, L"Remote LoadLibraryW did not finish within 30 seconds; path buffer retained for target safety");
        else oculus_set_error(s, GetLastError(), L"Waiting for remote LoadLibraryW failed");
        /* The target may still read this buffer. Deliberately retain it on timeout. */
        if (wait == WAIT_TIMEOUT) { CloseHandle(thread); free(path); return false; }
        goto cleanup;
    }
    OculusModule loaded;
    if (!oculus_find_module_by_path(s, path, &loaded)) {
        oculus_set_internal_error(s, L"LoadLibraryW returned, but '%ls' is not present in the target", path); goto cleanup;
    }
    wprintf(L"[+] Loaded %ls in target (module base: 0x%llX)\n",
            loaded.name, (unsigned long long)loaded.base);
    ok = true;
cleanup:
    if (thread) CloseHandle(thread);
    if (!VirtualFreeEx(s->process, remote, 0, MEM_RELEASE) && ok) {
        oculus_set_error(s, GetLastError(), L"DLL loaded, but remote path cleanup failed"); ok = false;
    }
    free(path); return ok;
}

