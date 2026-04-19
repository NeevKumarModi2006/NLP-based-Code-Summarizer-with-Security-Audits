
#include <stdio.h>
#include <string.h>

void process_input(char *user_input) {
    char buffer[10];
    
    // VULNERABLE: Buffer Overflow (strcpy doesn't check size)
    strcpy(buffer, user_input);
    
    // VULNERABLE: Format String
    printf(user_input);
    
    // VULNERABLE: Integer Overflow potential
    int size = strlen(user_input);
    char *dynamic = (char *)malloc(size); // checks needed
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_input(argv[1]);
    }
    return 0;
}
