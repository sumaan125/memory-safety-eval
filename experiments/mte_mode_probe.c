/*
 * mte_mode_probe.c - Phase 2/RQ3: synchronous vs asynchronous MTE reporting.
 *
 *   ./mte_mode_probe write   OOB store into a neighbouring "secret" object
 *   ./mte_mode_probe read    OOB loads that leak the neighbouring secret
 *
 * After the bad access the program executes a long syscall-free loop and
 * counts its progress in a global. The SIGSEGV handler prints how far the
 * program got before the fault was reported, the si_code, the reported
 * address, and whether the illegal store / leak actually took effect.
 *   SYNC : the faulting instruction never retires -> progress 0, exact addr.
 *   ASYNC: the fault is only raised at the next kernel entry -> the store
 *          has already happened / the leaked data has already been used.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ADDR_MASK ((((uintptr_t)1) << 56) - 1)
#define TAG(p) ((unsigned)(((uintptr_t)(p) >> 56) & 0xf))
#define LOOP 50000000UL

static volatile uint64_t progress;
static volatile uint64_t leaked_sum;
static volatile uint64_t bytes_leaked;
static uint64_t secret_sum;
static char *secret;
static const char *mode;

static void on_segv(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)uc;
    const char *c = si->si_code == 9 ? "SEGV_MTESERR(sync)" :
                    si->si_code == 8 ? "SEGV_MTEAERR(async)" : "other";
    printf("RESULT mode=%s si_code=%d %s fault_addr=%p progress_after_bug=%lu/%lu "
           "secret_first_byte=%c bytes_leaked=%lu leaked_sum_matches_secret=%s\n",
           mode, si->si_code, c, si->si_addr, (unsigned long)progress, LOOP,
           secret[0], (unsigned long)bytes_leaked, (leaked_sum == secret_sum && leaked_sum) ? "yes" : "no");
    fflush(stdout);
    _exit(3);
}

int main(int argc, char **argv)
{
    mode = argc > 1 ? argv[1] : "write";
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);

    char *a = (char *)malloc(32);
    secret = (char *)malloc(32);
    /* Make the demonstration deterministic: ensure the two tags differ. */
    while (TAG(a) == TAG(secret) && TAG(a) != 0) { free(secret); secret = (char *)malloc(32); }
    strcpy(secret, "TOP-SECRET-KEY-0123456789");
    for (int i = 0; i < 16; i++) secret_sum += (unsigned char)secret[i];

    size_t off = (size_t)((uintptr_t)secret & ADDR_MASK) - ((uintptr_t)a & ADDR_MASK);
    printf("a tag=%u secret tag=%u offset=%zu\n", TAG(a), TAG(secret), off);
    fflush(stdout);

    if (strcmp(mode, "write") == 0) {
        a[off] = '!';                                 /* illegal store */
    } else {
        for (int i = 0; i < 16; i++)                  /* illegal loads */
            { leaked_sum += (unsigned char)a[off + i]; bytes_leaked++; }
    }
    for (uint64_t i = 0; i < LOOP; i++) progress++;   /* no syscalls */

    /* First kernel entry after the bug. */
    printf("RESULT mode=%s no_fault progress_after_bug=%lu/%lu secret_first_byte=%c "
           "leaked_sum_matches_secret=%s\n", mode, (unsigned long)progress, LOOP, secret[0],
           (leaked_sum == secret_sum && leaked_sum) ? "yes" : "no");
    return 0;
}
