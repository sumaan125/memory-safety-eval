#include <stdio.h>
#include <stdlib.h>

int main() {
    int *ptr = (int *)malloc(sizeof(int));
    
    printf("Triggering Double-Free...\n");
    // First free (legal)
    free(ptr);
    
    // Second free (illegal vulnerability)
    free(ptr); 
    
    printf("Done.\n");
    return 0;
}