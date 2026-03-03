#include <unistd.h>
void run_prog(char *arg) {
    // VULNERABLE: Command Injection potential
    execl("/bin/sh", "sh", "-c", arg, NULL);
}