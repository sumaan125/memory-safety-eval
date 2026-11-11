/*
 * fault_reporter.c - linked into every test program (sources stay unmodified).
 *
 * Installs SA_SIGINFO handlers for the fatal signals a defense can raise and
 * prints one machine-readable line before re-raising the signal:
 *
 *   [FAULT] sig=SIGSEGV code=9(SEGV_MTESERR) addr=0x0b00... pc_off=0x8a4 module=/path/bin
 *
 * si_code distinguishes MTE synchronous (SEGV_MTESERR = 9) from asynchronous
 * (SEGV_MTEAERR = 8) tag-check faults; si_addr is the faulting address (0 in
 * async mode).  pc_off is the PC relative to the module base so the Python
 * runner can map it to file:line with addr2line.
 *
 * stdout is made unbuffered so that "Done." reliably shows whether execution
 * continued past the bug.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef SEGV_MTEAERR
#define SEGV_MTEAERR 8
#endif
#ifndef SEGV_MTESERR
#define SEGV_MTESERR 9
#endif

static const char *code_name(int sig, int code)
{
    if (sig == SIGSEGV) {
        switch (code) {
        case SEGV_MAPERR: return "SEGV_MAPERR";
        case SEGV_ACCERR: return "SEGV_ACCERR";
        case SEGV_MTEAERR: return "SEGV_MTEAERR";
        case SEGV_MTESERR: return "SEGV_MTESERR";
        }
    }
    if (code == SI_USER) return "SI_USER";
    if (code == SI_TKILL) return "SI_TKILL";
    return "OTHER";
}

static uintptr_t context_pc(void *uc_)
{
    ucontext_t *uc = (ucontext_t *)uc_;
#if defined(__aarch64__)
    return (uintptr_t)uc->uc_mcontext.pc;
#elif defined(__x86_64__)
    return (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
#else
    (void)uc;
    return 0;
#endif
}

static void handler(int sig, siginfo_t *si, void *uc)
{
    uintptr_t pc = context_pc(uc);
    Dl_info info;
    uintptr_t off = pc;
    const char *mod = "?";
    if (pc && dladdr((void *)pc, &info) && info.dli_fbase) {
        off = pc - (uintptr_t)info.dli_fbase;
        mod = info.dli_fname ? info.dli_fname : "?";
    }
    /* fprintf is not async-signal-safe, but the process is about to die and
     * this keeps the reporter simple; it is only used in test harnesses. */
    fprintf(stderr, "[FAULT] sig=%s code=%d(%s) addr=%p pc_off=0x%lx module=%s\n",
            sigabbrev_np(sig), si->si_code, code_name(sig, si->si_code),
            si->si_addr, (unsigned long)off, mod);
    fflush(stderr);
    signal(sig, SIG_DFL);
    raise(sig);
}

__attribute__((constructor)) static void fault_reporter_init(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    int sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGABRT};
    for (unsigned i = 0; i < sizeof sigs / sizeof sigs[0]; i++)
        sigaction(sigs[i], &sa, NULL);
}
