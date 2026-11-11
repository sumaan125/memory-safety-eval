/*
 * Boundary case B4: intra-object overflow that corrupts a code pointer.
 * The overflow stays inside one heap allocation (name[] -> handler), so
 * neither ASan (no redzones inside a struct) nor MTE (one tag per
 * allocation) can see it. The corrupted function pointer is then called,
 * i.e. a control-flow hijack -- the class of attack that CFI, not memory
 * tagging, is designed to stop. Index-based bounds instrumentation
 * (-fsanitize=bounds-strict) knows name[] has 16 elements and can trap.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct session {
    char name[16];
    void (*handler)(void);
};

static void greet(void) { printf("handler: normal greet()\n"); }
static void evil(void) { printf("handler: evil() -- CONTROL FLOW HIJACKED\n"); }

int main(void)
{
    struct session *s = (struct session *)malloc(sizeof *s);
    s->handler = greet;

    /* Attacker-controlled input: 16 filler bytes followed by a code pointer. */
    unsigned char input[16 + sizeof(void (*)(void))];
    memset(input, 'A', 16);
    void (*target)(void) = evil;
    memcpy(input + 16, &target, sizeof target);

    printf("Triggering intra-object overflow (copy %zu bytes into name[16])...\n", sizeof input);
    for (size_t i = 0; i < sizeof input; i++)
        s->name[i] = (char)input[i];

    s->handler();
    printf("Done.\n");
    free(s);
    return 0;
}
