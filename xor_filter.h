#ifndef _XOR_FILTER_H
#define _XOR_FILTER_H

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct xor_filter xorf_t;

struct xor_filter {
    size_t hash_seed[3];
    size_t capacity;
    uint64_t *fingerprint;
};

xorf_t *filter_new(char **key_set, size_t key_set_size);
void filter_free(xorf_t *filter);
bool filter_contains(xorf_t *filter, const char *item);

#endif