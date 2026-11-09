#include "oculus/oculus.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    bool verbose = false;
    SetConsoleCP(CP_UTF8); SetConsoleOutputCP(CP_UTF8);
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--verbose") == 0) verbose = true;
        else { fprintf(stderr, "Usage: oculus.exe [--verbose]\n"); return 1; }
    }
    return oculus_repl_run(verbose);
}
