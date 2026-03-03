#include <string.h>
#include <stdio.h>
void func(char *str) {
    char buffer[10];
    // VULNERABLE: Buffer Overflow
    strcpy(buffer, str);
}