#include "internal.h"
#include <stdarg.h>
#include <stdlib.h>

static int console_vwprintf(FILE *stream, const wchar_t *format, va_list ap) {
    va_list copy;
    va_copy(copy, ap);
    int chars = _vscwprintf(format, copy);
    va_end(copy);
    if (chars < 0) return chars;
    wchar_t *wide = (wchar_t *)malloc(((size_t)chars + 1) * sizeof(*wide));
    if (!wide) return -1;
    _vsnwprintf(wide, (size_t)chars + 1, format, ap);
    int bytes = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
    char *utf8 = bytes ? (char *)malloc((size_t)bytes) : NULL;
    int result = -1;
    if (utf8 && WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, bytes, NULL, NULL)) {
        result = fputs(utf8, stream);
    }
    free(utf8); free(wide); return result;
}

int oculus_wprintf(const wchar_t *format, ...) {
    va_list ap; va_start(ap, format); int result = console_vwprintf(stdout, format, ap); va_end(ap); return result;
}

int oculus_fwprintf(FILE *stream, const wchar_t *format, ...) {
    va_list ap; va_start(ap, format); int result = console_vwprintf(stream, format, ap); va_end(ap); return result;
}

static void append_system_message(wchar_t *dst, size_t cap, DWORD code) {
    wchar_t *msg = NULL;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                             FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code, 0,
                             (wchar_t *)&msg, 0, NULL);
    if (n && msg) {
        while (n && (msg[n - 1] == L'\r' || msg[n - 1] == L'\n' || msg[n - 1] == L' '))
            msg[--n] = L'\0';
        size_t used = wcslen(dst);
        if (used + 4 < cap)
            _snwprintf(dst + used, cap - used, L" — %ls", msg);
        LocalFree(msg);
    }
}

void oculus_set_error(OculusSession *s, DWORD code, const wchar_t *format, ...) {
    va_list ap;
    s->last_win32_error = code;
    va_start(ap, format);
    _vsnwprintf(s->last_error, OCULUS_MAX_ERROR - 1, format, ap);
    va_end(ap);
    s->last_error[OCULUS_MAX_ERROR - 1] = L'\0';
    size_t used = wcslen(s->last_error);
    if (used + 24 < OCULUS_MAX_ERROR)
        _snwprintf(s->last_error + used, OCULUS_MAX_ERROR - used,
                   L" (Win32 %lu)", (unsigned long)code);
    append_system_message(s->last_error, OCULUS_MAX_ERROR, code);
}

void oculus_set_internal_error(OculusSession *s, const wchar_t *format, ...) {
    va_list ap;
    s->last_win32_error = 0;
    va_start(ap, format);
    _vsnwprintf(s->last_error, OCULUS_MAX_ERROR - 1, format, ap);
    va_end(ap);
    s->last_error[OCULUS_MAX_ERROR - 1] = L'\0';
}

void oculus_print_error(const OculusSession *s) {
    fwprintf(stderr, L"[-] %ls\n", s->last_error[0] ? s->last_error : L"Unknown error");
}

bool oculus_utf8_to_wide(const char *src, wchar_t **dst) {
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, src, -1, NULL, 0);
    if (!n) return false;
    *dst = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!*dst) return false;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, src, -1, *dst, n)) {
        free(*dst); *dst = NULL; return false;
    }
    return true;
}

bool oculus_wide_to_utf8(const wchar_t *src, char **dst) {
    int n = WideCharToMultiByte(CP_UTF8, 0, src, -1, NULL, 0, NULL, NULL);
    if (!n) return false;
    *dst = (char *)malloc((size_t)n);
    if (!*dst) return false;
    if (!WideCharToMultiByte(CP_UTF8, 0, src, -1, *dst, n, NULL, NULL)) {
        free(*dst); *dst = NULL; return false;
    }
    return true;
}
