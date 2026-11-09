#ifndef OCULUS_OCULUS_H
#define OCULUS_OCULUS_H

#include <windows.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define OCULUS_MAX_ERROR 512
#define OCULUS_MAX_MODULE 260
#define OCULUS_MAX_EXPORT 256
#define OCULUS_MAX_PATCH 32

typedef enum OculusArchitecture {
    OCULUS_ARCH_UNKNOWN = 0,
    OCULUS_ARCH_X64
} OculusArchitecture;

typedef struct OculusHook {
    uint64_t id;
    DWORD process_id;
    wchar_t target_module[OCULUS_MAX_MODULE];
    char target_export[OCULUS_MAX_EXPORT];
    uintptr_t target_address;
    wchar_t replacement_module[OCULUS_MAX_MODULE];
    char replacement_export[OCULUS_MAX_EXPORT];
    uintptr_t replacement_address;
    size_t patch_length;
    unsigned char original[OCULUS_MAX_PATCH];
    DWORD original_protection;
    uintptr_t trampoline_address;
    size_t trampoline_size;
    bool active;
    struct OculusHook *next;
} OculusHook;

typedef struct OculusSession {
    HANDLE process;
    DWORD pid;
    OculusArchitecture architecture;
    wchar_t process_name[MAX_PATH];
    OculusHook *hooks;
    uint64_t next_hook_id;
    DWORD last_win32_error;
    wchar_t last_error[OCULUS_MAX_ERROR];
    bool verbose;
} OculusSession;

void oculus_session_init(OculusSession *session, bool verbose);
bool oculus_open_pid(OculusSession *session, uint32_t pid);
bool oculus_open_name(OculusSession *session, const wchar_t *name);
bool oculus_close(OculusSession *session);
bool oculus_list_modules(OculusSession *session);
bool oculus_list_exports(OculusSession *session, const wchar_t *module_name);
bool oculus_load_library(OculusSession *session, const wchar_t *path);
bool oculus_install_hook(OculusSession *session, const char *target_export,
                         const wchar_t *target_module,
                         const char *replacement_export,
                         const wchar_t *replacement_module, uint64_t *hook_id);
bool oculus_remove_hook(OculusSession *session, uint64_t hook_id);
void oculus_list_hooks(const OculusSession *session);
void oculus_print_status(const OculusSession *session);

/* Parse and execute one mutable UTF-8 input line. false means exit requested. */
bool oculus_repl_execute(OculusSession *session, char *line);
int oculus_repl_run(bool verbose);

#endif
