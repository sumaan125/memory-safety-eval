/*
 * bench_alloc.c - allocation-intensive workload.
 *   ./bench_alloc <min_size> <max_size> <ops> [live_slots]
 * Maintains `live_slots` live objects; each op frees a random slot and
 * allocates a new object of random size in [min,max], touching its first
 * and last byte. Allocator cost (and, under MTE, the cost of tagging every
 * new allocation) dominates.
 */
#include <stdio.h>
#include <stdlib.h>
#include "common.h"

int main(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: %s min max ops [slots]\n", argv[0]); return 2; }
    size_t lo = strtoul(argv[1], 0, 0), hi = strtoul(argv[2], 0, 0);
    long ops = atol(argv[3]);
    int slots = argc > 4 ? atoi(argv[4]) : 1024;
    char **live = calloc(slots, sizeof *live);
    uint64_t s = 0x9E3779B97F4A7C15ULL, sum = 0;
    for (long i = 0; i < ops; i++) {
        uint64_t r = rng_next(&s);
        int k = (int)(r % slots);
        size_t sz = lo + (size_t)((r >> 20) % (hi - lo + 1));
        if (live[k]) { sum += (unsigned char)live[k][0]; free(live[k]); }
        live[k] = malloc(sz);
        live[k][0] = (char)i;
        live[k][sz - 1] = (char)(i >> 8);
    }
    for (int k = 0; k < slots; k++) free(live[k]);
    free(live);
    printf("checksum %llu\n", (unsigned long long)sum);
    return 0;
}
