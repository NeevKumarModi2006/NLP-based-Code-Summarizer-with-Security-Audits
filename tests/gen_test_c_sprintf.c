#include <stdio.h>
void format(char *user) {
    char buffer[100];
    // VULNERABLE: Buffer Overflow
    sprintf(buffer, "User: %s", user);
}