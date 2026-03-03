#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void execute_command(char *cmd) {
    // VULN: Command Injection
    system(cmd);
}

void copy_data(char *input) {
    char buffer[64];
    // VULN: Buffer Overflow
    strcpy(buffer, input);
}

void log_message(char *user_msg) {
    // VULN: Format String
    printf(user_msg);
}

void insecure_temp() {
    // VULN: Insecure Temp File
    FILE *f = fopen("/tmp/tempfile", "w");
    if (f) {
        fprintf(f, "data");
        fclose(f);
    }
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        copy_data(argv[1]);
        execute_command(argv[1]);
        log_message(argv[1]);
    }
    char infinite_buffer[100];
    // VULN: Buffer Overflow (gets)
    gets(infinite_buffer);
    return 0;
}