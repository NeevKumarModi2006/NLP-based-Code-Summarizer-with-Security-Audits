#include <stdio.h>
void list(char *dir) {
    char cmd[100];
    sprintf(cmd, "ls %s", dir);
    // VULNERABLE: Command Injection
    popen(cmd, "r");
}