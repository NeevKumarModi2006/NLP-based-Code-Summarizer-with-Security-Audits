#include <string.h>
void copy(char *src, int len) {
    char dest[10];
    // VULNERABLE: Buffer Overflow
    memcpy(dest, src, len);
}