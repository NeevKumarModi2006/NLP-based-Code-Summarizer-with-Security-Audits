#include <stdio.h>
void func() {
    char buffer[10];
    // VULNERABLE: Buffer Overflow
    gets(buffer);
}