#include <stdio.h>
#include <stdlib.h>

int main() {
    int *array = (int *)malloc(100 * sizeof(int));
    
    printf("Triggering Use-After-Free (UAF)...\n");
    // Free the memory
    free(array);
    
    // The vulnerability: writing to the pointer after it has been freed
    array[0] = 42; 
    
    printf("Done.\n");
    return 0;
}