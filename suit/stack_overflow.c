#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    printf("Triggering stack buffer overflow...\n");
    // Writing 20 bytes into a 10-byte buffer
    strcpy(buffer, "AAAAAAAAAAAAAAAAAAAA"); 
    printf("Done.\n");
    return 0;
}