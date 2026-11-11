/*
 * bench_access.c - memory-access-intensive workload (one allocation).
 *   ./bench_access seq  <MiB> <passes>   streaming read-modify-write
 *   ./bench_access rand <MiB> <steps>    dependent random pointer chase
 * After set-up there are no allocations, so the overhead measured is the
 * per-access cost of checking (ASan instrumentation / MTE tag checks).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

int main(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: %s seq|rand MiB n\n", argv[0]); return 2; }
    size_t bytes = (size_t)atol(argv[2]) << 20;
    long n = atol(argv[3]);
    uint64_t sum = 0;
    if (strcmp(argv[1], "seq") == 0) {
        size_t cnt = bytes / sizeof(uint64_t);
        uint64_t *a = malloc(bytes);
        for (size_t i = 0; i < cnt; i++) a[i] = i;
        for (long p = 0; p < n; p++)
            for (size_t i = 0; i < cnt; i++) { sum += a[i]; a[i] = sum; }
        free(a);
    } else {
        /* 64-byte nodes linked in a random cyclic permutation. */
        struct node { struct node *next; uint64_t pad[7]; };
        size_t cnt = bytes / sizeof(struct node);
        struct node *v = malloc(cnt * sizeof *v);
        size_t *perm = malloc(cnt * sizeof *perm);
        uint64_t s = 42;
        for (size_t i = 0; i < cnt; i++) perm[i] = i;
        for (size_t i = cnt - 1; i > 0; i--) {
            size_t j = rng_next(&s) % (i + 1);
            size_t t = perm[i]; perm[i] = perm[j]; perm[j] = t;
        }
        for (size_t i = 0; i < cnt; i++) {
            v[perm[i]].next = &v[perm[(i + 1) % cnt]];
            v[perm[i]].pad[0] = i;
        }
        free(perm);
        struct node *c = &v[0];
        for (long i = 0; i < n; i++) { sum += c->pad[0]; c = c->next; }
        free(v);
    }
    printf("checksum %llu\n", (unsigned long long)sum);
    return 0;
}
