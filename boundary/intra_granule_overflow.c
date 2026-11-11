/*
 * Boundary case B1: intra-granule heap overflow.
 * A 10-byte allocation is padded to a 16-byte MTE granule. Writing byte 12
 * is out of bounds for the object but stays inside the object's own granule,
 * so it carries the same tag. ASan tracks bounds at byte precision (partial
 * shadow bytes) and should catch it; MTE cannot.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    char *buf = (char *)malloc(10);
    printf("Triggering intra-granule overflow (write buf[12] of a 10-byte object)...\n");
    buf[12] = 'X';
    printf("Done.\n");
    free(buf);
    return 0;
}
