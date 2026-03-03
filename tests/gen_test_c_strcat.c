#include <string.h>
void append(char *dest, char *src) {
    // VULNERABLE: Buffer Overflow
    strcat(dest, src);
}