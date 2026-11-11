/*
 * Boundary case B2: non-linear out-of-bounds write that lands inside another
 * live object. The index is computed so that a + idx points into b, skipping
 * over ASan's redzone. ASan only checks the shadow of the target address,
 * which is valid (it belongs to b), so it should miss this. MTE compares the
 * pointer tag of `a` with the memory tag of `b`, which differ with
 * probability ~15/16 (exact rate measured in experiments/mte_tag_space).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define ADDR_MASK ((((uintptr_t)1) << 56) - 1) /* strip the MTE tag byte */

int main(void)
{
    char *a = (char *)malloc(64);
    char *b = (char *)malloc(64);
    b[8] = 'b';
    size_t idx = (size_t)(((uintptr_t)b & ADDR_MASK) - ((uintptr_t)a & ADDR_MASK)) + 8;
    printf("Triggering far OOB write a[%zu] (lands inside live object b)...\n", idx);
    a[idx] = 'X';
    printf("Done. b[8] is now '%c'\n", b[8]);
    free(b);
    free(a);
    return 0;
}
