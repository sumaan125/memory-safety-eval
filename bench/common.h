#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H
#include <stdint.h>
/* xorshift64* PRNG: deterministic and identical across platforms. */
static inline uint64_t rng_next(uint64_t *s)
{
    uint64_t x = *s;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    *s = x;
    return x * 0x2545F4914F6CDD1DULL;
}
#endif
