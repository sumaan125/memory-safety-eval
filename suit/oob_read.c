#include <stdio.h>
#include <stdlib.h>

int main() {
    int *arr = (int *)malloc(5 * sizeof(int));
    
    printf("Triggering Out-of-Bounds Read...\n");
    // Illegal read past the allocated 5 elements (indices 0-4)
    volatile int leak = arr[5]; 
    
    printf("Done.\n");
    free(arr);
    return 0;
}