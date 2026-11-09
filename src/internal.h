#ifndef OCULUS_INTERNAL_H
#define OCULUS_INTERNAL_H

#include "oculus/oculus.h"
#include <tlhelp32.h>
#include <stdio.h>

int oculus_wprintf(const wchar_t *format, ...);
int oculus_fwprintf(FILE *stream, const wchar_t *format, ...);
#define wprintf oculus_wprintf
#define fwprintf oculus_fwprintf

typedef struct OculusModule {
    uintptr_t base;
    size_t size;
    wchar_t name[MAX_PATH];
    wchar_t path[32768];
} OculusModule;

typedef struct OculusResolvedExport {
    uintptr_t address;
    OculusModule module;
    bool forwarded;
    char forwarder[512];
} OculusResolvedExport;

void oculus_set_error(OculusSession *s, DWORD code, const wchar_t *format, ...);
void oculus_set_internal_error(OculusSession *s, const wchar_t *format, ...);
void oculus_print_error(const OculusSession *s);
bool oculus_require_session(OculusSession *s, const wchar_t *operation);
bool oculus_target_alive(OculusSession *s);
bool oculus_utf8_to_wide(const char *src, wchar_t **dst);
bool oculus_wide_to_utf8(const wchar_t *src, char **dst);

bool oculus_find_module(OculusSession *s, const wchar_t *name, OculusModule *out);
bool oculus_find_module_by_path(OculusSession *s, const wchar_t *path, OculusModule *out);
bool oculus_resolve_export(OculusSession *s, const wchar_t *module,
                           const char *symbol, OculusResolvedExport *out);
bool oculus_read_remote(OculusSession *s, uintptr_t address, void *buffer,
                        size_t length, const OculusModule *bounds);

typedef struct OculusX64Instruction {
    uint8_t length;
    bool rip_relative;
    bool relative_branch;
} OculusX64Instruction;
bool oculus_x64_decode(const uint8_t *code, size_t available, OculusX64Instruction *out);

#endif
