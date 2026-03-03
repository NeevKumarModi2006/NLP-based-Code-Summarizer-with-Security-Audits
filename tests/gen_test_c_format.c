#include <stdio.h>
void log(char *msg) {
    // VULNERABLE: Format String
    printf(msg);
}