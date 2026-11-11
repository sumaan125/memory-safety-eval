/*
 * bench_kv.c - small application-level workload: in-memory key-value store
 * (chained hash table, heap-allocated keys/values) driven by a
 * 70% GET / 20% PUT / 10% DELETE mix over a skewed key space.
 *   ./bench_kv <ops> [keyspace]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

#define NBUCKETS (1u << 16)

struct entry {
    struct entry *next;
    char *key;
    char *val;
    size_t vlen;
};

static struct entry *table[NBUCKETS];

static uint32_t hash(const char *k)
{
    uint32_t h = 2166136261u;
    while (*k) { h ^= (unsigned char)*k++; h *= 16777619u; }
    return h;
}

static struct entry **lookup(const char *k)
{
    struct entry **e = &table[hash(k) & (NBUCKETS - 1)];
    while (*e && strcmp((*e)->key, k) != 0) e = &(*e)->next;
    return e;
}

static void put(const char *k, size_t vlen, uint64_t seed)
{
    struct entry **e = lookup(k);
    char *v = malloc(vlen);
    memset(v, (int)(seed & 0xff), vlen);
    if (*e) { free((*e)->val); (*e)->val = v; (*e)->vlen = vlen; return; }
    struct entry *n = malloc(sizeof *n);
    n->key = strdup(k);
    n->val = v;
    n->vlen = vlen;
    n->next = NULL;
    *e = n;
}

static void del(const char *k)
{
    struct entry **e = lookup(k);
    if (!*e) return;
    struct entry *d = *e;
    *e = d->next;
    free(d->key); free(d->val); free(d);
}

int main(int argc, char **argv)
{
    long ops = argc > 1 ? atol(argv[1]) : 1000000;
    long keys = argc > 2 ? atol(argv[2]) : 100000;
    uint64_t s = 7, sum = 0;
    char k[32];
    for (long i = 0; i < keys; i++) {
        snprintf(k, sizeof k, "key%08ld", i);
        put(k, 16 + rng_next(&s) % 497, s);
    }
    for (long i = 0; i < ops; i++) {
        uint64_t r = rng_next(&s);
        long id = (long)((r % keys) * (r % keys) / keys); /* skew to low ids */
        snprintf(k, sizeof k, "key%08ld", id);
        unsigned op = (unsigned)((r >> 32) % 100);
        if (op < 70) {
            struct entry *e = *lookup(k);
            if (e) for (size_t j = 0; j < e->vlen; j += 64) sum += (unsigned char)e->val[j];
        } else if (op < 90) {
            put(k, 16 + (r >> 40) % 497, r);
        } else {
            del(k);
        }
    }
    for (unsigned b = 0; b < NBUCKETS; b++)
        while (table[b]) { struct entry *d = table[b]; table[b] = d->next; free(d->key); free(d->val); free(d); }
    printf("checksum %llu\n", (unsigned long long)sum);
    return 0;
}
