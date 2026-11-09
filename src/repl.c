#include "internal.h"
#include "repl_parser.h"
#include <ctype.h>
#include <errno.h>
#include <io.h>
#include <stdlib.h>
#include <string.h>

static char *dup_text(const char *s) {
    size_t n = strlen(s) + 1; char *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

void oculus_tokens_free(char **argv, size_t argc) {
    for (size_t i = 0; i < argc; ++i) free(argv[i]);
    free(argv);
}

bool oculus_tokenize(const char *line, char ***argv_out, size_t *argc_out, char **error_out) {
    char **argv = NULL; size_t argc = 0, capacity = 0; const char *p = line;
    if ((unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB &&
        (unsigned char)p[2] == 0xBF) p += 3; /* UTF-8 BOM from redirected PowerShell input. */
    *argv_out = NULL; *argc_out = 0; if (error_out) *error_out = NULL;
    while (*p) {
        while (*p && isspace((unsigned char)*p)) ++p;
        if (!*p) break;
        size_t cap = 32, len = 0; char *word = (char *)malloc(cap); bool quoted = false;
        if (!word) goto oom;
        while (*p && (quoted || !isspace((unsigned char)*p))) {
            if (*p == '"') { quoted = !quoted; ++p; continue; }
            if (*p == '\\' && p[1] == '"') { ++p; }
            if (len + 1 >= cap) {
                cap *= 2; char *next = (char *)realloc(word, cap);
                if (!next) { free(word); goto oom; } word = next;
            }
            word[len++] = *p++;
        }
        if (quoted) {
            free(word); oculus_tokens_free(argv, argc);
            if (error_out) *error_out = dup_text("unterminated quote");
            return false;
        }
        word[len] = '\0';
        if (argc == capacity) {
            capacity = capacity ? capacity * 2 : 8;
            char **next = (char **)realloc(argv, capacity * sizeof(*argv));
            if (!next) { free(word); goto oom; } argv = next;
        }
        argv[argc++] = word;
    }
    *argv_out = argv; *argc_out = argc; return true;
oom:
    oculus_tokens_free(argv, argc);
    if (error_out) *error_out = dup_text("out of memory");
    return false;
}

static bool equals(const char *a, const char *b) { return _stricmp(a, b) == 0; }

static void help(void) {
    puts("Commands:\n"
         "  help\n"
         "  open <decimal-pid|process.exe>\n"
         "  close\n"
         "  list process\n"
         "  list dlls\n"
         "  list functions:<module.dll>\n"
         "  list functions <module.dll>\n"
         "  load \"C:\\absolute path\\library.dll\"\n"
         "  hook <Export>:<module.dll> <Replacement>:<module.dll>\n"
         "  hooks\n"
         "  unhook <id>\n"
         "  status\n"
         "  exit | quit\n\n"
         "An existing attachment must be closed before opening another process.");
}

static bool wide_arg(OculusSession *s, const char *arg, wchar_t **out) {
    if (oculus_utf8_to_wide(arg, out)) return true;
    oculus_set_error(s, GetLastError(), L"Argument is not valid UTF-8"); return false;
}

static bool parse_endpoint(OculusSession *s, const char *text, char **symbol, wchar_t **module) {
    const char *colon = strchr(text, ':');
    if (!colon || colon == text || !colon[1]) {
        oculus_set_internal_error(s, L"Endpoint must use Export:module.dll syntax"); return false;
    }
    size_t n = (size_t)(colon - text); *symbol = (char *)malloc(n + 1);
    if (!*symbol) { oculus_set_internal_error(s, L"Out of memory"); return false; }
    memcpy(*symbol, text, n); (*symbol)[n] = '\0';
    if (!wide_arg(s, colon + 1, module)) { free(*symbol); *symbol = NULL; return false; }
    return true;
}

bool oculus_repl_execute(OculusSession *s, char *line) {
    char **av = NULL, *parse_error = NULL; size_t ac = 0; bool success = true, keep_running = true;
    if (!oculus_tokenize(line, &av, &ac, &parse_error)) {
        fprintf(stderr, "[-] Parse error: %s\n", parse_error ? parse_error : "unknown"); free(parse_error); return true;
    }
    if (!ac) goto done;
    if (equals(av[0], "help") && ac == 1) help();
    else if ((equals(av[0], "exit") || equals(av[0], "quit")) && ac == 1) {
        if (s->process && !oculus_close(s)) success = false; else keep_running = false;
    } else if (equals(av[0], "open") && ac == 2) {
        char *end = NULL; errno = 0; unsigned long long pid = strtoull(av[1], &end, 10);
        if (!errno && end && *end == '\0' && pid <= UINT32_MAX) success = oculus_open_pid(s, (uint32_t)pid);
        else { wchar_t *name = NULL; if (wide_arg(s, av[1], &name)) { success = oculus_open_name(s, name); free(name); } else success = false; }
    } else if (equals(av[0], "close") && ac == 1) success = oculus_close(s);
    else if (equals(av[0], "status") && ac == 1) oculus_print_status(s);
    else if (equals(av[0], "hooks") && ac == 1) {
        if ((success = oculus_require_session(s, L"hooks"))) oculus_list_hooks(s);
    } else if (equals(av[0], "unhook") && ac == 2) {
        char *end = NULL; unsigned long long id = strtoull(av[1], &end, 10);
        if (!end || *end || !id) { oculus_set_internal_error(s, L"unhook requires a positive numeric ID"); success = false; }
        else if ((success = oculus_require_session(s, L"unhook"))) success = oculus_remove_hook(s, (uint64_t)id);
    } else if (equals(av[0], "list") && ac == 2 &&
               (equals(av[1], "process") || equals(av[1], "processes"))) {
        success = oculus_list_processes(s);
    } else if (equals(av[0], "list") && ac == 2 && equals(av[1], "dlls")) success = oculus_list_modules(s);
    else if (equals(av[0], "list") && ac == 2 && _strnicmp(av[1], "functions:", 10) == 0 && av[1][10]) {
        wchar_t *module = NULL; if (wide_arg(s, av[1] + 10, &module)) { success = oculus_list_exports(s, module); free(module); } else success = false;
    } else if (equals(av[0], "list") && ac == 3 && equals(av[1], "functions")) {
        wchar_t *module = NULL; if (wide_arg(s, av[2], &module)) { success = oculus_list_exports(s, module); free(module); } else success = false;
    } else if (equals(av[0], "load") && ac == 2) {
        wchar_t *path = NULL; if (wide_arg(s, av[1], &path)) { success = oculus_load_library(s, path); free(path); } else success = false;
    } else if (equals(av[0], "hook") && ac == 3) {
        char *ts = NULL, *rs = NULL; wchar_t *tm = NULL, *rm = NULL; uint64_t id;
        if (parse_endpoint(s, av[1], &ts, &tm) && parse_endpoint(s, av[2], &rs, &rm))
            success = oculus_install_hook(s, ts, tm, rs, rm, &id);
        else success = false;
        free(ts); free(rs); free(tm); free(rm);
    } else {
        oculus_set_internal_error(s, L"Unknown command or wrong arguments; type 'help'"); success = false;
    }
    if (!success) oculus_print_error(s);
done:
    oculus_tokens_free(av, ac); return keep_running;
}

static char *read_line(void) {
    size_t cap = 256, len = 0; char *line = (char *)malloc(cap);
    if (!line) return NULL;
    int c;
    while ((c = fgetc(stdin)) != EOF && c != '\n') {
        if (c == '\r') continue;
        if (len + 1 >= cap) { cap *= 2; char *next = (char *)realloc(line, cap); if (!next) { free(line); return NULL; } line = next; }
        line[len++] = (char)c;
    }
    if (c == EOF && !len) { free(line); return NULL; }
    line[len] = '\0'; return line;
}

int oculus_repl_run(bool verbose) {
    OculusSession session; oculus_session_init(&session, verbose);
    puts("Oculus — Windows Runtime Debugging REPL\nType 'help' for commands.");
    bool interactive = _isatty(_fileno(stdin)) != 0;
    for (;;) {
        if (interactive) { fputs("oculus> ", stdout); fflush(stdout); }
        char *line = read_line();
        if (!line) break;
        bool keep = oculus_repl_execute(&session, line); free(line);
        if (!keep) return 0;
    }
    if (session.process && !oculus_close(&session)) {
        oculus_print_error(&session);
        fputs("[-] EOF cleanup failed; target may still contain session hooks\n", stderr); return 2;
    }
    return 0;
}
