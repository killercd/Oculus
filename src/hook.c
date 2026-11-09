#include "internal.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define ABS_JUMP_SIZE 14u

typedef struct SuspendedThreads {
    HANDLE *handles;
    DWORD *ids;
    size_t count;
    size_t capacity;
} SuspendedThreads;

static bool executable_protection(DWORD p) {
    p &= 0xFFu;
    return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
           p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

static void make_abs_jump(unsigned char out[ABS_JUMP_SIZE], uintptr_t destination) {
    out[0] = 0xFF; out[1] = 0x25;
    memset(out + 2, 0, 4);
    uint64_t address = (uint64_t)destination;
    memcpy(out + 6, &address, sizeof(address));
}

static LPVOID allocate_near_target(OculusSession *s, uintptr_t target, size_t size) {
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    uintptr_t granularity = (uintptr_t)info.dwAllocationGranularity;
    uintptr_t base = target & ~(granularity - 1u);
    uintptr_t minimum = (uintptr_t)info.lpMinimumApplicationAddress;
    uintptr_t maximum = (uintptr_t)info.lpMaximumApplicationAddress;
    const uintptr_t range = UINT64_C(0x70000000);

    for (uintptr_t distance = granularity; distance <= range; distance += granularity) {
        if (base >= distance && base - distance >= minimum) {
            LPVOID memory = VirtualAllocEx(s->process, (LPVOID)(base - distance), size,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (memory) return memory;
        }
        if (base <= UINTPTR_MAX - distance) {
            uintptr_t candidate = base + distance;
            if (candidate <= maximum && size <= maximum - candidate) {
                LPVOID memory = VirtualAllocEx(s->process, (LPVOID)candidate, size,
                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (memory) return memory;
            }
        }
    }
    oculus_set_internal_error(s, L"Cannot allocate a trampoline within relocation range of 0x%llX",
                              (unsigned long long)target);
    return NULL;
}

static bool relocate_prologue(OculusSession *s, uintptr_t target, uintptr_t trampoline,
                              const unsigned char *original, size_t length,
                              unsigned char *relocated) {
    memcpy(relocated, original, length);
    size_t offset = 0;
    while (offset < length) {
        OculusX64Instruction ins;
        if (!oculus_x64_decode(original + offset, length - offset, &ins) ||
            !ins.length || offset + ins.length > length) {
            oculus_set_internal_error(s, L"Cannot re-decode prologue at offset %zu", offset);
            return false;
        }
        if (ins.rip_relative) {
            int32_t old_displacement;
            memcpy(&old_displacement, original + offset + ins.displacement_offset,
                   sizeof(old_displacement));
            int64_t referenced = (int64_t)(target + offset + ins.length) + old_displacement;
            int64_t new_displacement = referenced -
                (int64_t)(trampoline + offset + ins.length);
            if (new_displacement < INT32_MIN || new_displacement > INT32_MAX) {
                oculus_set_internal_error(s, L"RIP-relative instruction at offset %zu is out of trampoline range",
                                          offset);
                return false;
            }
            int32_t adjusted = (int32_t)new_displacement;
            memcpy(relocated + offset + ins.displacement_offset, &adjusted, sizeof(adjusted));
        }
        if (ins.relative_branch) {
            int64_t old_displacement;
            if (ins.relative_size == 1) {
                int8_t value;
                memcpy(&value, original + offset + ins.relative_offset, sizeof(value));
                old_displacement = value;
            } else if (ins.relative_size == 4) {
                int32_t value;
                memcpy(&value, original + offset + ins.relative_offset, sizeof(value));
                old_displacement = value;
            } else {
                oculus_set_internal_error(s, L"Unsupported relative operand at offset %zu", offset);
                return false;
            }
            int64_t destination = (int64_t)(target + offset + ins.length) + old_displacement;
            if (destination >= (int64_t)target && destination < (int64_t)(target + length))
                destination = (int64_t)trampoline + (destination - (int64_t)target);
            int64_t adjusted = destination - (int64_t)(trampoline + offset + ins.length);
            if (ins.relative_size == 1) {
                if (adjusted < INT8_MIN || adjusted > INT8_MAX) {
                    oculus_set_internal_error(s, L"Short relative branch at offset %zu cannot be relocated", offset);
                    return false;
                }
                int8_t value = (int8_t)adjusted;
                memcpy(relocated + offset + ins.relative_offset, &value, sizeof(value));
            } else {
                if (adjusted < INT32_MIN || adjusted > INT32_MAX) {
                    oculus_set_internal_error(s, L"Relative branch at offset %zu is out of trampoline range", offset);
                    return false;
                }
                int32_t value = (int32_t)adjusted;
                memcpy(relocated + offset + ins.relative_offset, &value, sizeof(value));
            }
        }
        offset += ins.length;
    }
    return true;
}

static bool has_id(const SuspendedThreads *set, DWORD id) {
    for (size_t i = 0; i < set->count; ++i) if (set->ids[i] == id) return true;
    return false;
}

static void resume_threads(SuspendedThreads *set) {
    for (size_t i = set->count; i > 0; --i) {
        ResumeThread(set->handles[i - 1]);
        CloseHandle(set->handles[i - 1]);
    }
    free(set->handles); free(set->ids); ZeroMemory(set, sizeof(*set));
}

static bool add_thread(SuspendedThreads *set, HANDLE h, DWORD id) {
    if (set->count == set->capacity) {
        size_t next = set->capacity ? set->capacity * 2 : 16;
        HANDLE *handles = (HANDLE *)realloc(set->handles, next * sizeof(*handles));
        if (!handles) return false;
        set->handles = handles;
        DWORD *ids = (DWORD *)realloc(set->ids, next * sizeof(*ids));
        if (!ids) return false;
        set->ids = ids; set->capacity = next;
    }
    set->handles[set->count] = h; set->ids[set->count] = id; ++set->count; return true;
}

static bool ip_in_range(uint64_t ip, uintptr_t base, size_t size) {
    return size && ip >= (uint64_t)base && ip - (uint64_t)base < size;
}

static bool suspend_target(OculusSession *s, uintptr_t danger1, size_t size1,
                           uintptr_t danger2, size_t size2, SuspendedThreads *set) {
    ZeroMemory(set, sizeof(*set));
    unsigned stable = 0;
    for (unsigned pass = 0; pass < 8 && stable < 2; ++pass) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            oculus_set_error(s, GetLastError(), L"Cannot enumerate target threads"); resume_threads(set); return false;
        }
        THREADENTRY32 te = {0}; te.dwSize = sizeof(te); size_t added = 0;
        if (Thread32First(snap, &te)) do {
            if (te.th32OwnerProcessID != s->pid || has_id(set, te.th32ThreadID)) continue;
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                  FALSE, te.th32ThreadID);
            if (!h) { CloseHandle(snap); oculus_set_error(s, GetLastError(), L"Cannot open thread %lu", (unsigned long)te.th32ThreadID); resume_threads(set); return false; }
            if (SuspendThread(h) == (DWORD)-1) {
                DWORD e = GetLastError(); CloseHandle(h);
                if (e == ERROR_INVALID_PARAMETER) continue;
                CloseHandle(snap); oculus_set_error(s, e, L"Cannot suspend thread %lu", (unsigned long)te.th32ThreadID); resume_threads(set); return false;
            }
            CONTEXT ctx; ZeroMemory(&ctx, sizeof(ctx)); ctx.ContextFlags = CONTEXT_CONTROL;
            if (!GetThreadContext(h, &ctx)) {
                DWORD e = GetLastError(); ResumeThread(h); CloseHandle(h); CloseHandle(snap);
                oculus_set_error(s, e, L"Cannot inspect suspended thread %lu", (unsigned long)te.th32ThreadID); resume_threads(set); return false;
            }
            if (ip_in_range(ctx.Rip, danger1, size1) || ip_in_range(ctx.Rip, danger2, size2)) {
                ResumeThread(h); CloseHandle(h); CloseHandle(snap);
                oculus_set_internal_error(s, L"Thread %lu is executing in code that must be patched; retry later",
                                          (unsigned long)te.th32ThreadID); resume_threads(set); return false;
            }
            if (!add_thread(set, h, te.th32ThreadID)) {
                ResumeThread(h); CloseHandle(h); CloseHandle(snap);
                oculus_set_internal_error(s, L"Out of memory tracking suspended threads"); resume_threads(set); return false;
            }
            ++added;
        } while (Thread32Next(snap, &te));
        CloseHandle(snap);
        stable = added ? 0 : stable + 1;
    }
    if (stable < 2) {
        oculus_set_internal_error(s, L"Target thread list did not stabilize; hook refused"); resume_threads(set); return false;
    }
    return true;
}

static bool query_executable(OculusSession *s, uintptr_t address, const wchar_t *label,
                             MEMORY_BASIC_INFORMATION *mbi) {
    if (!VirtualQueryEx(s->process, (LPCVOID)address, mbi, sizeof(*mbi))) {
        oculus_set_error(s, GetLastError(), L"VirtualQueryEx failed for %ls address 0x%llX",
                         label, (unsigned long long)address); return false;
    }
    if (mbi->State != MEM_COMMIT || !executable_protection(mbi->Protect) || (mbi->Protect & PAGE_GUARD)) {
        oculus_set_internal_error(s, L"%ls address 0x%llX is not executable committed memory",
                                  label, (unsigned long long)address); return false;
    }
    return true;
}

static bool configure_sample_original(OculusSession *s, const wchar_t *replacement_module,
                                      uintptr_t trampoline) {
    OculusResolvedExport setter;
    if (!oculus_resolve_export(s, replacement_module, "OculusSetOriginal", &setter)) {
        if (s->verbose)
            wprintf(L"[debug] %ls has no optional OculusSetOriginal export\n",
                    replacement_module);
        s->last_error[0] = L'\0'; s->last_win32_error = 0; return true; /* Optional convention. */
    }
    HANDLE thread = CreateRemoteThread(s->process, NULL, 0,
                    (LPTHREAD_START_ROUTINE)(uintptr_t)setter.address, (LPVOID)trampoline, 0, NULL);
    if (!thread) { oculus_set_error(s, GetLastError(), L"Cannot call optional OculusSetOriginal"); return false; }
    DWORD wait = WaitForSingleObject(thread, 5000); CloseHandle(thread);
    if (wait != WAIT_OBJECT_0) { oculus_set_internal_error(s, L"Optional OculusSetOriginal did not complete"); return false; }
    if (s->verbose)
        wprintf(L"[debug] Configured OculusSetOriginal with trampoline 0x%llX\n",
                (unsigned long long)trampoline);
    return true;
}

bool oculus_install_hook(OculusSession *s, const char *target_export,
                         const wchar_t *target_module, const char *replacement_export,
                         const wchar_t *replacement_module, uint64_t *hook_id) {
    if (!oculus_require_session(s, L"hook")) return false;
    OculusResolvedExport target, replacement;
    if (!oculus_resolve_export(s, target_module, target_export, &target) ||
        !oculus_resolve_export(s, replacement_module, replacement_export, &replacement)) return false;
    if (target.address == replacement.address) {
        oculus_set_internal_error(s, L"Target and replacement resolve to the same address"); return false;
    }
    for (OculusHook *h = s->hooks; h; h = h->next) {
        uintptr_t a = target.address, b = h->target_address;
        if ((a >= b && a - b < h->patch_length) || (b >= a && b - a < OCULUS_MAX_PATCH)) {
            oculus_set_internal_error(s, L"Target overlaps active hook %llu", (unsigned long long)h->id); return false;
        }
    }
    MEMORY_BASIC_INFORMATION tmem, rmem;
    if (!query_executable(s, target.address, L"target", &tmem) ||
        !query_executable(s, replacement.address, L"replacement", &rmem)) return false;
    size_t region_left = (size_t)((uintptr_t)tmem.BaseAddress + tmem.RegionSize - target.address);
    if (region_left < OCULUS_MAX_PATCH) {
        oculus_set_internal_error(s, L"Target prologue crosses a memory-region boundary"); return false;
    }
    unsigned char probe[OCULUS_MAX_PATCH]; SIZE_T got = 0;
    if (!ReadProcessMemory(s->process, (LPCVOID)target.address, probe, sizeof(probe), &got) || got != sizeof(probe)) {
        oculus_set_error(s, GetLastError(), L"Cannot read target prologue"); return false;
    }
    size_t patch_length = 0;
    while (patch_length < ABS_JUMP_SIZE) {
        OculusX64Instruction ins;
        if (!oculus_x64_decode(probe + patch_length, sizeof(probe) - patch_length, &ins)) {
            oculus_set_internal_error(s, L"Unsupported x64 instruction at prologue offset %zu", patch_length); return false;
        }
        patch_length += ins.length;
        if (patch_length > OCULUS_MAX_PATCH) { oculus_set_internal_error(s, L"Decoded prologue is too large"); return false; }
    }
    SuspendedThreads threads;
    if (!suspend_target(s, target.address, patch_length, 0, 0, &threads)) return false;
    unsigned char verify[OCULUS_MAX_PATCH];
    if (!ReadProcessMemory(s->process, (LPCVOID)target.address, verify, patch_length, &got) ||
        got != patch_length || memcmp(verify, probe, patch_length) != 0) {
        oculus_set_internal_error(s, L"Target prologue changed while preparing hook"); resume_threads(&threads); return false;
    }
    size_t trampoline_size = patch_length + ABS_JUMP_SIZE;
    LPVOID trampoline = allocate_near_target(s, target.address, trampoline_size);
    if (!trampoline) { resume_threads(&threads); return false; }
    unsigned char trampoline_bytes[OCULUS_MAX_PATCH + ABS_JUMP_SIZE];
    if (!relocate_prologue(s, target.address, (uintptr_t)trampoline, probe,
                           patch_length, trampoline_bytes)) {
        VirtualFreeEx(s->process, trampoline, 0, MEM_RELEASE);
        resume_threads(&threads);
        return false;
    }
    make_abs_jump(trampoline_bytes + patch_length, target.address + patch_length);
    bool patched = false, ok = false; DWORD trampoline_old = 0, patch_old = 0;
    if (!WriteProcessMemory(s->process, trampoline, trampoline_bytes, trampoline_size, &got) || got != trampoline_size) {
        oculus_set_error(s, GetLastError(), L"Cannot write trampoline"); goto rollback;
    }
    if (!VirtualProtectEx(s->process, trampoline, trampoline_size, PAGE_EXECUTE_READ, &trampoline_old) ||
        !FlushInstructionCache(s->process, trampoline, trampoline_size)) {
        oculus_set_error(s, GetLastError(), L"Cannot make trampoline executable"); goto rollback;
    }
    unsigned char patch[OCULUS_MAX_PATCH]; memset(patch, 0x90, patch_length);
    make_abs_jump(patch, replacement.address);
    if (!VirtualProtectEx(s->process, (LPVOID)target.address, patch_length, PAGE_EXECUTE_READWRITE, &patch_old)) {
        oculus_set_error(s, GetLastError(), L"Cannot change target protection"); goto rollback;
    }
    if (!WriteProcessMemory(s->process, (LPVOID)target.address, patch, patch_length, &got) || got != patch_length) {
        oculus_set_error(s, GetLastError(), L"Cannot write inline hook");
        WriteProcessMemory(s->process, (LPVOID)target.address, probe, patch_length, &got);
        DWORD ignored; VirtualProtectEx(s->process, (LPVOID)target.address, patch_length, patch_old, &ignored);
        goto rollback;
    }
    patched = true;
    { DWORD ignored;
      if (!VirtualProtectEx(s->process, (LPVOID)target.address, patch_length, patch_old, &ignored) ||
          !FlushInstructionCache(s->process, (LPCVOID)target.address, patch_length)) {
          oculus_set_error(s, GetLastError(), L"Cannot finalize hook protection/cache"); goto rollback;
      }
    }
    OculusHook *record = (OculusHook *)calloc(1, sizeof(*record));
    if (!record) { oculus_set_internal_error(s, L"Out of memory registering hook"); goto rollback; }
    record->id = s->next_hook_id++; record->process_id = s->pid;
    wcsncpy(record->target_module, target_module, OCULUS_MAX_MODULE - 1);
    strncpy(record->target_export, target_export, OCULUS_MAX_EXPORT - 1);
    record->target_address = target.address;
    wcsncpy(record->replacement_module, replacement_module, OCULUS_MAX_MODULE - 1);
    strncpy(record->replacement_export, replacement_export, OCULUS_MAX_EXPORT - 1);
    record->replacement_address = replacement.address; record->patch_length = patch_length;
    memcpy(record->original, probe, patch_length); record->original_protection = patch_old;
    record->trampoline_address = (uintptr_t)trampoline; record->trampoline_size = trampoline_size;
    record->active = true; record->next = s->hooks; s->hooks = record;
    resume_threads(&threads);
    if (!configure_sample_original(s, replacement_module, (uintptr_t)trampoline)) {
        oculus_print_error(s); /* Hook remains usable; calling original is an optional convention. */
    }
    wprintf(L"[+] Inline hook installed: %ls!%hs -> %ls!%hs\n[+] Hook ID: %llu (trampoline 0x%016llX)\n",
           target_module, target_export, replacement_module, replacement_export,
           (unsigned long long)record->id, (unsigned long long)record->trampoline_address);
    if (hook_id) *hook_id = record->id;
    return true;
rollback:
    if (patched) {
        DWORD old, ignored;
        if (VirtualProtectEx(s->process, (LPVOID)target.address, patch_length, PAGE_EXECUTE_READWRITE, &old)) {
            WriteProcessMemory(s->process, (LPVOID)target.address, probe, patch_length, &got);
            VirtualProtectEx(s->process, (LPVOID)target.address, patch_length, patch_old, &ignored);
            FlushInstructionCache(s->process, (LPCVOID)target.address, patch_length);
        }
    }
    VirtualFreeEx(s->process, trampoline, 0, MEM_RELEASE); resume_threads(&threads); return ok;
}

bool oculus_remove_hook(OculusSession *s, uint64_t hook_id) {
    OculusHook **link = &s->hooks;
    while (*link && (*link)->id != hook_id) link = &(*link)->next;
    if (!*link) { oculus_set_internal_error(s, L"Hook %llu does not exist", (unsigned long long)hook_id); return false; }
    OculusHook *h = *link; DWORD exit_code = STILL_ACTIVE;
    if (!GetExitCodeProcess(s->process, &exit_code) || exit_code != STILL_ACTIVE) {
        *link = h->next; free(h); return true; /* Remote address space no longer exists. */
    }
    SuspendedThreads threads;
    if (!suspend_target(s, h->target_address, h->patch_length,
                        h->trampoline_address, h->trampoline_size, &threads)) return false;
    unsigned char expected[OCULUS_MAX_PATCH], current[OCULUS_MAX_PATCH]; SIZE_T got = 0;
    memset(expected, 0x90, h->patch_length); make_abs_jump(expected, h->replacement_address);
    if (!ReadProcessMemory(s->process, (LPCVOID)h->target_address, current, h->patch_length, &got) ||
        got != h->patch_length || memcmp(current, expected, h->patch_length) != 0) {
        oculus_set_internal_error(s, L"Hook %llu target bytes were modified externally; refusing blind restore",
                                  (unsigned long long)hook_id); resume_threads(&threads); return false;
    }
    DWORD old = 0, ignored = 0;
    if (!VirtualProtectEx(s->process, (LPVOID)h->target_address, h->patch_length,
                          PAGE_EXECUTE_READWRITE, &old)) {
        oculus_set_error(s, GetLastError(), L"Failed to make hook %llu writable", (unsigned long long)hook_id);
        resume_threads(&threads); return false;
    }
    if (!WriteProcessMemory(s->process, (LPVOID)h->target_address, h->original, h->patch_length, &got) ||
        got != h->patch_length) {
        DWORD error = GetLastError();
        VirtualProtectEx(s->process, (LPVOID)h->target_address, h->patch_length, old, &ignored);
        oculus_set_error(s, error, L"Failed to restore bytes for hook %llu", (unsigned long long)hook_id);
        resume_threads(&threads); return false;
    }
    if (!VirtualProtectEx(s->process, (LPVOID)h->target_address, h->patch_length,
                          h->original_protection, &ignored) ||
        !FlushInstructionCache(s->process, (LPCVOID)h->target_address, h->patch_length)) {
        oculus_set_error(s, GetLastError(), L"Hook bytes restored, but protection/cache finalization failed");
        resume_threads(&threads); return false;
    }
    bool freed = VirtualFreeEx(s->process, (LPVOID)h->trampoline_address, 0, MEM_RELEASE) != 0;
    *link = h->next; free(h); resume_threads(&threads);
    if (!freed) fputs("[!] Original restored, but the remote trampoline could not be released\n", stderr);
    printf("[+] Hook %llu removed; original instructions restored\n", (unsigned long long)hook_id);
    return true;
}

void oculus_list_hooks(const OculusSession *s) {
    puts("ID   TARGET                                      REPLACEMENT                                 STATUS");
    for (const OculusHook *h = s->hooks; h; h = h->next)
        wprintf(L"%-4llu %ls!%hs  ->  %ls!%hs  %ls\n", (unsigned long long)h->id,
                h->target_module, h->target_export, h->replacement_module,
                h->replacement_export, h->active ? L"active" : L"inactive");
}
