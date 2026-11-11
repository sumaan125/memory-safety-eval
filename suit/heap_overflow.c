#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // Allocate 10 bytes on the heap
    char *heap_buffer = (char *)malloc(10);
    
    printf("Triggering heap buffer overflow...\n");
    // Write 20 bytes into the 10-byte allocation
    strcpy(heap_buffer, "AAAAAAAAAAAAAAAAAAAA"); 
    printf("Done.\n");
    
    free(heap_buffer);
    return 0;
}