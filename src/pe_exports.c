#include "internal.h"
#include <stdlib.h>
#include <string.h>

typedef struct ExportView {
    OculusModule module;
    IMAGE_EXPORT_DIRECTORY dir;
    DWORD export_rva;
    DWORD export_size;
    DWORD *functions;
    DWORD *names;
    WORD *ordinals;
} ExportView;

bool oculus_read_remote(OculusSession *s, uintptr_t address, void *buffer,
                        size_t length, const OculusModule *bounds) {
    if (!length) return true;
    if (bounds) {
        if (address < bounds->base || length > bounds->size ||
            address - bounds->base > bounds->size - length) {
            oculus_set_internal_error(s, L"Remote PE read at 0x%llX is outside module '%ls'",
                                      (unsigned long long)address, bounds->name);
            return false;
        }
    }
    SIZE_T got = 0;
    if (!ReadProcessMemory(s->process, (LPCVOID)address, buffer, length, &got) || got != length) {
        oculus_set_error(s, GetLastError(), L"ReadProcessMemory failed at 0x%llX (%zu bytes)",
                         (unsigned long long)address, length);
        return false;
    }
    return true;
}

static bool checked_rva(OculusSession *s, const OculusModule *m, DWORD rva,
                        size_t length, uintptr_t *address) {
    if ((size_t)rva > m->size || length > m->size - (size_t)rva) {
        oculus_set_internal_error(s, L"Malformed PE in '%ls': RVA 0x%lX is out of bounds",
                                  m->name, (unsigned long)rva);
        return false;
    }
    *address = m->base + (uintptr_t)rva;
    return true;
}

static void free_view(ExportView *v) {
    free(v->functions); free(v->names); free(v->ordinals);
    ZeroMemory(v, sizeof(*v));
}

static bool load_array(OculusSession *s, const OculusModule *m, DWORD rva,
                       size_t count, size_t element, void **out) {
    if (count && element > SIZE_MAX / count) {
        oculus_set_internal_error(s, L"Malformed export array size"); return false;
    }
    size_t bytes = count * element; uintptr_t address;
    if (!checked_rva(s, m, rva, bytes, &address)) return false;
    void *p = bytes ? malloc(bytes) : NULL;
    if (bytes && !p) { oculus_set_internal_error(s, L"Out of memory reading exports"); return false; }
    if (bytes && !oculus_read_remote(s, address, p, bytes, m)) { free(p); return false; }
    *out = p; return true;
}

static bool open_exports(OculusSession *s, const OculusModule *module, ExportView *v) {
    ZeroMemory(v, sizeof(*v)); v->module = *module;
    IMAGE_DOS_HEADER dos;
    if (!oculus_read_remote(s, module->base, &dos, sizeof(dos), module)) return false;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) {
        oculus_set_internal_error(s, L"Module '%ls' has an invalid DOS header", module->name); return false;
    }
    uintptr_t nt_address;
    if (!checked_rva(s, module, (DWORD)dos.e_lfanew, sizeof(IMAGE_NT_HEADERS64), &nt_address)) return false;
    IMAGE_NT_HEADERS64 nt;
    if (!oculus_read_remote(s, nt_address, &nt, sizeof(nt), module)) return false;
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        oculus_set_internal_error(s, L"Module '%ls' is not a valid PE32+ image", module->name); return false;
    }
    IMAGE_DATA_DIRECTORY dd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd.VirtualAddress || !dd.Size) {
        oculus_set_internal_error(s, L"Module '%ls' has no export directory", module->name); return false;
    }
    uintptr_t dir_address;
    if (!checked_rva(s, module, dd.VirtualAddress, dd.Size, &dir_address)) return false;
    if (!checked_rva(s, module, dd.VirtualAddress, sizeof(v->dir), &dir_address)) return false;
    if (!oculus_read_remote(s, dir_address, &v->dir, sizeof(v->dir), module)) return false;
    v->export_rva = dd.VirtualAddress; v->export_size = dd.Size;
    if (v->dir.NumberOfFunctions > 1000000 || v->dir.NumberOfNames > v->dir.NumberOfFunctions) {
        oculus_set_internal_error(s, L"Module '%ls' has unreasonable export counts", module->name); return false;
    }
    if (!load_array(s, module, v->dir.AddressOfFunctions, v->dir.NumberOfFunctions,
                    sizeof(DWORD), (void **)&v->functions) ||
        !load_array(s, module, v->dir.AddressOfNames, v->dir.NumberOfNames,
                    sizeof(DWORD), (void **)&v->names) ||
        !load_array(s, module, v->dir.AddressOfNameOrdinals, v->dir.NumberOfNames,
                    sizeof(WORD), (void **)&v->ordinals)) {
        free_view(v); return false;
    }
    return true;
}

static bool read_remote_string(OculusSession *s, const OculusModule *m, DWORD rva,
                               char *out, size_t cap) {
    uintptr_t address;
    if (!cap || !checked_rva(s, m, rva, 1, &address)) return false;
    size_t max = m->size - (size_t)rva;
    for (size_t i = 0; i + 1 < cap && i < max; ++i) {
        if (!oculus_read_remote(s, address + i, &out[i], 1, m)) return false;
        if (!out[i]) return true;
    }
    out[cap - 1] = '\0';
    oculus_set_internal_error(s, L"Malformed or overlong string in module '%ls'", m->name);
    return false;
}

static bool is_forwarder(const ExportView *v, DWORD rva) {
    uint64_t start = v->export_rva, end = start + v->export_size;
    return (uint64_t)rva >= start && (uint64_t)rva < end;
}

bool oculus_list_exports(OculusSession *s, const wchar_t *module_name) {
    if (!oculus_require_session(s, L"list functions")) return false;
    OculusModule m; ExportView v;
    if (!oculus_find_module(s, module_name, &m) || !open_exports(s, &m, &v)) return false;
    printf("EXPORT                                           ORDINAL  ADDRESS             FORWARDER\n");
    for (DWORD fi = 0; fi < v.dir.NumberOfFunctions; ++fi) {
        DWORD rva = v.functions[fi];
        if (!rva) continue; /* Sparse export-table slot, not an ordinal-only export. */
        const char *display = "<ordinal-only>"; char name[OCULUS_MAX_EXPORT];
        for (DWORD ni = 0; ni < v.dir.NumberOfNames; ++ni) {
            if ((DWORD)v.ordinals[ni] == fi) {
                if (!read_remote_string(s, &m, v.names[ni], name, sizeof(name))) { free_view(&v); return false; }
                display = name; break;
            }
        }
        char forward[512] = "";
        if (rva && (size_t)rva >= m.size) {
            DWORD ordinal = v.dir.Base + fi;
            free_view(&v); oculus_set_internal_error(s, L"Export ordinal %lu has an out-of-range RVA",
                                                     (unsigned long)ordinal); return false;
        }
        if (rva && is_forwarder(&v, rva) && !read_remote_string(s, &m, rva, forward, sizeof(forward))) {
            free_view(&v); return false;
        }
        printf("%-48s %-8lu 0x%016llX  %s\n", display,
               (unsigned long)(v.dir.Base + fi),
               (unsigned long long)(rva ? m.base + rva : 0), forward);
    }
    free_view(&v); return true;
}

static bool resolve_recursive(OculusSession *s, const wchar_t *module_name,
                              const char *symbol, unsigned depth, OculusResolvedExport *out) {
    if (depth > 16) { oculus_set_internal_error(s, L"Export forwarder chain is too deep"); return false; }
    OculusModule m; ExportView v;
    if (!oculus_find_module(s, module_name, &m) || !open_exports(s, &m, &v)) return false;
    DWORD index = UINT32_MAX;
    if (symbol[0] == '#') {
        char *end = NULL; unsigned long ordinal = strtoul(symbol + 1, &end, 10);
        if (!end || *end || ordinal < v.dir.Base || ordinal - v.dir.Base >= v.dir.NumberOfFunctions) {
            free_view(&v); oculus_set_internal_error(s, L"Invalid or missing ordinal '%hs' in '%ls'", symbol, m.name); return false;
        }
        index = (DWORD)(ordinal - v.dir.Base);
    } else {
        char name[OCULUS_MAX_EXPORT];
        for (DWORD i = 0; i < v.dir.NumberOfNames; ++i) {
            if (!read_remote_string(s, &m, v.names[i], name, sizeof(name))) { free_view(&v); return false; }
            if (strcmp(name, symbol) == 0) { index = v.ordinals[i]; break; }
        }
    }
    if (index == UINT32_MAX || index >= v.dir.NumberOfFunctions || !v.functions[index]) {
        free_view(&v); oculus_set_internal_error(s, L"Export '%hs' was not found in '%ls'", symbol, m.name); return false;
    }
    DWORD rva = v.functions[index];
    if (is_forwarder(&v, rva)) {
        char forward[512];
        if (!read_remote_string(s, &m, rva, forward, sizeof(forward))) { free_view(&v); return false; }
        char *dot = strrchr(forward, '.');
        if (!dot || dot == forward || !dot[1]) {
            free_view(&v); oculus_set_internal_error(s, L"Malformed forwarder '%hs'", forward); return false;
        }
        *dot = '\0';
        wchar_t wide_module[300];
        int n = MultiByteToWideChar(CP_ACP, 0, forward, -1, wide_module, 260);
        if (!n) { free_view(&v); oculus_set_error(s, GetLastError(), L"Cannot decode forwarder module"); return false; }
        if (!wcschr(wide_module, L'.')) wcscat(wide_module, L".dll");
        if (s->verbose) wprintf(L"[debug] Forwarder %ls!%hs -> %ls!%hs\n", m.name, symbol, wide_module, dot + 1);
        free_view(&v);
        bool ok = resolve_recursive(s, wide_module, dot + 1, depth + 1, out);
        if (ok) {
            out->forwarded = true;
            _snprintf(out->forwarder, sizeof(out->forwarder), "%s", forward);
        }
        return ok;
    }
    if ((size_t)rva >= m.size) {
        free_view(&v); oculus_set_internal_error(s, L"Export '%hs' has an out-of-range RVA", symbol); return false;
    }
    ZeroMemory(out, sizeof(*out)); out->address = m.base + rva; out->module = m;
    free_view(&v); return true;
}

bool oculus_resolve_export(OculusSession *s, const wchar_t *module,
                           const char *symbol, OculusResolvedExport *out) {
    return resolve_recursive(s, module, symbol, 0, out);
}
