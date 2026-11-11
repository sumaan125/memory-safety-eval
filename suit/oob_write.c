#include <stdio.h>
#include <stdlib.h>

int main() {
    int *arr = (int *)malloc(5 * sizeof(int));
    
    printf("Triggering Out-of-Bounds Write...\n");
    // Illegal write past the allocated 5 elements (indices 0-4)
    arr[5] = 99; 
    
    printf("Done.\n");
    free(arr);
    return 0;
}