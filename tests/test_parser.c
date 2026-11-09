#include "oculus/oculus.h"
#include "repl_parser.h"
#include "internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void parser_tests(void) {
    char **v; size_t n; char *error;
    assert(oculus_tokenize("  load   \"C:\\path with spaces\\x.dll\"  ", &v, &n, &error));
    assert(n == 2); assert(strcmp(v[0], "load") == 0);
    assert(strcmp(v[1], "C:\\path with spaces\\x.dll") == 0); oculus_tokens_free(v, n);
    assert(oculus_tokenize("hook A:a.dll B:b.dll", &v, &n, &error));
    assert(n == 3); oculus_tokens_free(v, n);
    assert(oculus_tokenize("\xEF\xBB\xBFopen 123", &v, &n, &error));
    assert(n == 2 && strcmp(v[0], "open") == 0); oculus_tokens_free(v, n);
    assert(!oculus_tokenize("load \"missing", &v, &n, &error));
    assert(error && strcmp(error, "unterminated quote") == 0); free(error);
}

static void decoder_tests(void) {
    OculusX64Instruction ins;
    const unsigned char nop[] = {0x90};
    assert(oculus_x64_decode(nop, sizeof(nop), &ins)); assert(ins.length == 1);
    const unsigned char mov[] = {0x48, 0x89, 0xE5};
    assert(oculus_x64_decode(mov, sizeof(mov), &ins)); assert(ins.length == 3 && !ins.rip_relative);
    const unsigned char rip[] = {0x48, 0x8B, 0x05, 1, 0, 0, 0};
    assert(oculus_x64_decode(rip, sizeof(rip), &ins));
    assert(ins.rip_relative && ins.displacement_offset == 3 && ins.displacement_size == 4);
    const unsigned char call[] = {0xE8, 0, 0, 0, 0};
    assert(oculus_x64_decode(call, sizeof(call), &ins));
    assert(ins.relative_branch && ins.relative_offset == 1 && ins.relative_size == 4);
    const unsigned char vex[] = {0xC5, 0xF8, 0x77};
    assert(!oculus_x64_decode(vex, sizeof(vex), &ins));
}

int main(void) {
    parser_tests(); decoder_tests();
    puts("parser/decoder tests passed"); return 0;
}
