#ifndef OCULUS_REPL_PARSER_H
#define OCULUS_REPL_PARSER_H
#include <stdbool.h>
#include <stddef.h>
bool oculus_tokenize(const char *line, char ***argv_out, size_t *argc_out, char **error_out);
void oculus_tokens_free(char **argv, size_t argc);
#endif
