
#include <stdio.h>
#include <string.h>
#include <windows.h>

int main(void) {
    char input[100];

    printf("Inserisci una stringa: ");

    if (scanf("%99s", input) != 1) {
        return 1;
    }

    if (strcmp(input, "msg") == 0) {
        MessageBoxA(
            NULL,
            "Questo e' un messaggio!",
            "MessageBoxA",
            MB_OK | MB_ICONINFORMATION
        );
    }

    return 0;
}
