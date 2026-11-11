/*
 * mte_tag_space.c - Phase 4: controlled experiments on MTE's finite tag space.
 * AArch64 only; run with glibc heap tagging in synchronous mode:
 *     GLIBC_TUNABLES=glibc.mem.tagging=3 ./mte_tag_space [trials]
 *
 * Each "probe" is a single tagged load. A tag-check fault is caught with
 * sigsetjmp/siglongjmp so thousands of probes run in one process. Loads are
 * used instead of stores so that undetected probes never corrupt the heap.
 *
 *   E1 granule      : for request size n, where does the first fault occur?
 *   E2 distance     : detection rate of an OOB load d bytes past the end of
 *                     an object surrounded by live neighbours.
 *   E3 reuse        : stale-pointer detection after free and after the chunk
 *                     is re-allocated (accidental tag match probability).
 *   E4 histogram    : distribution of tags handed out by the allocator.
 *   E5 irg          : correlation between consecutive IRG-generated tags.
 *
 * Output: CSV sections introduced by "#section <name>".
 */
#define _GNU_SOURCE
#include <malloc.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ADDR_MASK ((((uintptr_t)1) << 56) - 1)
#define TAG(p) ((unsigned)(((uintptr_t)(p) >> 56) & 0xf))
#define ADDR(p) ((uintptr_t)(p) & ADDR_MASK)

static sigjmp_buf jb;
static volatile sig_atomic_t last_code;

static void on_segv(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)uc;
    last_code = si->si_code;
    siglongjmp(jb, 1);
}

/* Returns 1 if the load faulted (tag mismatch), 0 otherwise. */
static int probe(const volatile char *p)
{
    if (sigsetjmp(jb, 1) == 0) {
        volatile char v = *p;
        (void)v;
        return 0;
    }
    return 1;
}

static void e1_granule(int trials)
{
    printf("#section granule\n");
    printf("request,usable_size,rounded16,first_fault_mode,frac_at_rounded,frac_fault_within_64\n");
    for (int n = 1; n <= 64; n++) {
        int rounded = (n + 15) & ~15;
        int hist[129] = {0};
        int at_rounded = 0, any = 0;
        size_t usable = 0;
        for (int t = 0; t < trials; t++) {
            char *p = (char *)malloc(n);
            usable = malloc_usable_size(p);
            int first = -1;
            for (int off = n; off < n + 64; off++)
                if (probe(p + off)) { first = off; break; }
            if (first >= 0) { any++; hist[first]++; if (first == rounded) at_rounded++; }
            free(p);
        }
        int mode = -1, best = 0;
        for (int i = 0; i < 129; i++) if (hist[i] > best) { best = hist[i]; mode = i; }
        printf("%d,%zu,%d,%d,%.4f,%.4f\n", n, usable, rounded, mode,
               (double)at_rounded / trials, (double)any / trials);
    }
}

#define POOL 64
static void e2_distance(int trials)
{
    printf("#section distance\n");
    printf("obj_size,distance_past_end,trials,detected,rate\n");
    const int sz = 48;
    char *pool[POOL];
    for (int i = 0; i < POOL; i++) pool[i] = (char *)malloc(sz);
    for (int d = 0; d <= 1024; d += 16) {
        int det = 0;
        for (int t = 0; t < trials; t++) {
            /* Re-allocate every object so that all tags are re-randomised. */
            for (int i = 0; i < POOL; i++) free(pool[i]);
            for (int i = 0; i < POOL; i++) pool[i] = (char *)malloc(sz);
            det += probe(pool[POOL / 4] + sz + d);
        }
        printf("%d,%d,%d,%d,%.4f\n", sz, d, trials, det, (double)det / trials);
    }
    for (int i = 0; i < POOL; i++) free(pool[i]);
}

/* Read the allocation tag stored in memory for address p (LDG). */
static unsigned mem_tag(const void *p)
{
    void *r = (void *)p;
    __asm__ volatile(".arch_extension memtag\n\tldg %0, [%0]" : "+r"(r));
    return TAG(r);
}

static void e3_reuse(int trials)
{
    /* For each trial: p = malloc; free(p); q = malloc (same size).
     * t_alloc = tag of p, t_free = memory tag right after free,
     * t_realloc = tag of q. A stale access through p is undetected iff
     * t_realloc == t_alloc. */
    printf("#section reuse\n");
    printf("trials,detected_after_free,same_address_realloc,tag_collision,detected_after_realloc,"
           "undetected_after_realloc,free_tag_eq_alloc_tag,realloc_tag_eq_free_tag\n");
    int det_free = 0, same = 0, coll = 0, det_re = 0, undet_re = 0, f_eq_a = 0, r_eq_f = 0;
    static int trans[16][16]; /* t_alloc -> t_realloc */
    static int dfree[16], dre[16]; /* (t_free - t_alloc) mod 16, (t_realloc - t_free) mod 16 */
    char *keep = (char *)malloc(64); /* keeps the chunk away from top */
    for (int t = 0; t < trials; t++) {
        char *p = (char *)malloc(64);
        unsigned ta = TAG(p);
        free(p);
        unsigned tf = mem_tag(p);
        det_free += probe(p);
        char *q = (char *)malloc(64);
        if (ADDR(q) == ADDR(p)) {
            unsigned tr = TAG(q);
            same++;
            trans[ta][tr]++;
            dfree[(tf - ta) & 15]++;
            dre[(tr - tf) & 15]++;
            if (tr == ta) coll++;
            if (tf == ta) f_eq_a++;
            if (tr == tf) r_eq_f++;
            if (probe(p)) det_re++; else undet_re++;
        }
        free(q);
    }
    free(keep);
    printf("%d,%d,%d,%d,%d,%d,%d,%d\n", trials, det_free, same, coll, det_re, undet_re, f_eq_a, r_eq_f);
    printf("#section reuse_transition\n");
    printf("alloc_tag,realloc_tag,count\n");
    for (int a = 0; a < 16; a++)
        for (int b = 0; b < 16; b++)
            if (trans[a][b]) printf("%d,%d,%d\n", a, b, trans[a][b]);
    printf("#section reuse_tag_delta\n");
    printf("delta_mod16,free_minus_alloc,realloc_minus_free\n");
    for (int d = 0; d < 16; d++) printf("%d,%d,%d\n", d, dfree[d], dre[d]);
}

static void e4_histogram(int n)
{
    printf("#section tag_histogram\n");
    printf("tag,count\n");
    long cnt[16] = {0};
    for (int i = 0; i < n; i++) {
        char *p = (char *)malloc(32);
        cnt[TAG(p)]++;
        free(p);
    }
    for (int t = 0; t < 16; t++) printf("%d,%ld\n", t, cnt[t]);
}

/* Minimal parser: with _GNU_SOURCE, glibc >= 2.38 headers redirect atoi to
 * __isoc23_strtol, which the glibc 2.36 runtime does not provide. */
static int parse_int(const char *s)
{
    int v = 0;
    while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
    return v;
}

/* E5: quality of the hardware tag generator (IRG) itself: how often do two
 * consecutive IRG results coincide? Ideal (uniform over 15 tags): 1/15. */
static void e5_irg(int n)
{
    printf("#section irg\n");
    printf("samples,p_equal_lag1,p_equal_lag2,ideal\n");
    unsigned prev2 = 16, prev1 = 16;
    long eq1 = 0, eq2 = 0;
    for (int i = 0; i < n; i++) {
        void *r = (void *)0x1000;
        uint64_t excl = 1; /* exclude tag 0, as glibc/Linux do */
        __asm__ volatile(".arch_extension memtag\n\tirg %0, %0, %1" : "+r"(r) : "r"(excl));
        unsigned t = TAG(r);
        if (t == prev1) eq1++;
        if (t == prev2) eq2++;
        prev2 = prev1; prev1 = t;
    }
    printf("%d,%.4f,%.4f,%.4f\n", n, (double)eq1 / n, (double)eq2 / n, 1.0 / 15);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    int trials = argc > 1 ? parse_int(argv[1]) : 1000;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);

    char *t = (char *)malloc(16);
    printf("#info heap_tagging=%s\n", TAG(t) ? "on" : "off(or tag 0)");
    free(t);

    e1_granule(trials / 5 > 0 ? trials / 5 : 1);
    e2_distance(trials);
    e3_reuse(trials * 20);
    e4_histogram(trials * 100);
    e5_irg(trials * 100);
    return 0;
}
