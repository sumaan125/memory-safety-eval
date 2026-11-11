/*
 * Boundary case B3: use-after-free after the freed chunk has been reused.
 * ASan holds freed memory in a FIFO quarantine (256 MiB by default on
 * x86-64). Once enough memory has been freed after `victim`, its chunk leaves
 * quarantine and may be handed out again; a dangling write then hits a valid,
 * live object and ASan cannot see it. MTE re-tags memory on every free and
 * malloc, so the stale pointer's tag mismatches with probability ~15/16.
 *
 * argv[1] = MiB of allocation churn used to flush the quarantine (default 320).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ADDR_MASK ((((uintptr_t)1) << 56) - 1)
#define NLIVE 20000

int main(int argc, char **argv)
{
    long churn_mib = argc > 1 ? atol(argv[1]) : 320;
    char *victim = (char *)malloc(64);
    free(victim);

    /* Flush the quarantine with large short-lived allocations. */
    for (long i = 0; i < churn_mib; i++) {
        char *p = (char *)malloc(1 << 20);
        p[0] = 1;
        free(p);
    }

    /* Allocate many same-size objects; one of them is expected to reuse the
     * victim's chunk. */
    static char *live[NLIVE];
    int reused = -1;
    for (int i = 0; i < NLIVE; i++) {
        live[i] = (char *)malloc(64);
        memset(live[i], 0, 64);
        if (reused < 0 && ((uintptr_t)live[i] & ADDR_MASK) == ((uintptr_t)victim & ADDR_MASK))
            reused = i;
    }
    printf("victim chunk reused by live object: %s\n", reused >= 0 ? "yes" : "no");
    printf("Triggering use-after-free write through stale pointer...\n");
    victim[0] = 'X';
    printf("Done.\n");
    for (int i = 0; i < NLIVE; i++)
        free(live[i]);
    return 0;
}
