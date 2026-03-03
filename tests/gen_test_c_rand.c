#include <stdlib.h>
int get_token() {
    // VULNERABLE: Weak Random
    return rand();
}