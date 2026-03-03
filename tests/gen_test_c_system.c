#include <stdlib.h>
void run(char *cmd) {
    // VULNERABLE: Command Injection
    system(cmd);
}