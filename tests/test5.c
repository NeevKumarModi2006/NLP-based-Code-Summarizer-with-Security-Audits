#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void execute_user_req(char *input) {
    char command[128];
    // VULNERABILITY 1: Buffer Overflow (no bounds checking)
    strcpy(command, "echo ");
    strcat(command, input);

    // VULNERABILITY 2: Command Injection (direct system call)
    system(command);
}

int main() {
    char user_buf[1024];
    printf("Enter request: ");
    gets(user_buf); // VULNERABILITY 3: Highly dangerous function (gets)
    execute_user_req(user_buf);
    return 0;
}