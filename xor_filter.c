#include "xor_filter.h"

typedef struct _xorf_list_element _xorf_list_element_t;
typedef struct _xorf_list _xorf_list_t;
typedef struct _xorf_hash_mask _xorf_hash_mask_t;

struct _xorf_list_element {
    size_t index;
    uint64_t mask;
    _xorf_list_element_t *next;
};

struct _xorf_list {
    _xorf_list_element_t *head;
    _xorf_list_element_t *tail;
    size_t size;
};

struct _xorf_hash_mask {
    uint64_t mask;
    size_t count;
};

/* Internal functions for construction of Xor Filter */
/* Hash functions */
static uint64_t _xorf_djb2_hash_64(const char *key);
static uint64_t _xorf_hash_64(const uint64_t hash_key, uint64_t seed);
static uint64_t _xorf_hash_index(const uint64_t hash_key,
                                 size_t *hash_seed,
                                 size_t hash_index,
                                 size_t capacity);
static size_t _xorf_random_hash_seed();

/* Construction functions */

_xorf_list_t *_xorf_mapping(char **key_set,
                            size_t key_set_size,
                            size_t *hash_seed);
uint64_t *_xorf_fingerprint_init(_xorf_list_t *stack, size_t *hash_seed);

/* Internal Hash Set functions for set in mapping step */
_xorf_hash_mask_t *_xorf_mask_new(size_t capacity);
void _xorf_mask_free(_xorf_hash_mask_t *mask);
void _xorf_hash_set_init(char **key_set,
                         size_t ket_set_size,
                         _xorf_hash_mask_t *mask_set,
                         size_t *hash_seed,
                         size_t capacity);
long _xorf_hash_set_scan(_xorf_hash_mask_t *mask_set, size_t capacity);

/* Internal List functions for stack in mapping step */
_xorf_list_t *_xorf_list_new();
void _xorf_list_free(_xorf_list_t *l);
bool _xorf_list_insert_head(_xorf_list_t *l, size_t index, uint64_t mask);
bool _xorf_list_remove_head(_xorf_list_t *l);
size_t _xorf_list_size(_xorf_list_t *l);

/* Internal List Element functions for list */
_xorf_list_element_t *_xorf_list_element_new(size_t index, uint64_t mask);
void _xorf_list_element_free(_xorf_list_element_t *e);

/* The implementations of external functions for user */
xorf_t *filter_new(char **key_set, size_t key_set_size)
{
    srand(time(NULL));
    xorf_t *filter = malloc(sizeof(xorf_t));
    _xorf_list_t *stack = NULL;

    do {
        filter->hash_seed[0] = _xorf_random_hash_seed();
        filter->hash_seed[1] = _xorf_random_hash_seed();
        filter->hash_seed[2] = _xorf_random_hash_seed();

        stack = _xorf_mapping(key_set, key_set_size, filter->hash_seed);
    } while (!stack);

    filter->fingerprint = _xorf_fingerprint_init(stack, filter->hash_seed);
    filter->capacity = (1.23 * key_set_size + 32) / 3;
    filter->capacity *= 3;
    _xorf_list_free(stack);
    return filter;
}

void filter_free(xorf_t *filter)
{
    free(filter->fingerprint);
    free(filter);
}

bool filter_contains(xorf_t *filter, const char *item)
{
    uint64_t mask = _xorf_djb2_hash_64(item);
    uint64_t H0 = filter->fingerprint[_xorf_hash_index(
        mask, filter->hash_seed, 0, filter->capacity / 3)];
    uint64_t H1 = filter->fingerprint[_xorf_hash_index(
        mask, filter->hash_seed, 1, filter->capacity / 3)];
    uint64_t H2 = filter->fingerprint[_xorf_hash_index(
        mask, filter->hash_seed, 2, filter->capacity / 3)];

    return mask == (filter->fingerprint[_xorf_hash_index(
                        mask, filter->hash_seed, 0, filter->capacity / 3)] ^
                    filter->fingerprint[_xorf_hash_index(
                        mask, filter->hash_seed, 1, filter->capacity / 3)] ^
                    filter->fingerprint[_xorf_hash_index(
                        mask, filter->hash_seed, 2, filter->capacity / 3)]);
}

/* The implementations of internal functions for construction of Xor Filter */

static uint64_t _xorf_djb2_hash_64(const char *key)
{
    uint64_t hash = 5381;
    int c;
    while ((c = *key++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

static uint64_t _xorf_hash_64(const uint64_t hash_key, uint64_t seed)
{
    uint64_t hash = hash_key + seed;
    hash = (hash ^ (hash >> 33)) * 0xff51afd7ed558ccd;
    hash = (hash ^ (hash >> 33)) * 0xc4ceb9fe1a85ec53;
    return hash;
}

static uint64_t _xorf_hash_index(const uint64_t hash_key,
                                 size_t *hash_seed,
                                 size_t hash_index,
                                 size_t capacity)
{
    uint64_t hash = _xorf_hash_64(hash_key, hash_seed[hash_index]);
    return ((hash) % capacity) + hash_index * capacity;
}

static size_t _xorf_random_hash_seed()
{
    size_t head = rand();
    head <<= 32;
    size_t tail = rand();
    return head | tail;
}

_xorf_list_t *_xorf_mapping(char **key_set,
                            size_t key_set_size,
                            size_t *hash_seed)
{
    size_t capacity = ((size_t) floor(1.23 * key_set_size) + 32) / 3 * 3;
    _xorf_list_t *stack = _xorf_list_new();
    _xorf_hash_mask_t *mask_set = _xorf_mask_new(capacity);

    _xorf_hash_set_init(key_set, key_set_size, mask_set, hash_seed, capacity);
    long index = _xorf_hash_set_scan(mask_set, capacity);
    while (index != -1) {
        uint64_t hash = mask_set[index].mask;
        _xorf_list_insert_head(stack, index, hash);
        uint64_t h0 = _xorf_hash_index(hash, hash_seed, 0, capacity / 3);
        uint64_t h1 = _xorf_hash_index(hash, hash_seed, 1, capacity / 3);
        uint64_t h2 = _xorf_hash_index(hash, hash_seed, 2, capacity / 3);
        mask_set[h0].mask ^= hash;
        mask_set[h0].count--;
        mask_set[h1].mask ^= hash;
        mask_set[h1].count--;
        mask_set[h2].mask ^= hash;
        mask_set[h2].count--;

        index = _xorf_hash_set_scan(mask_set, capacity);
    }

    _xorf_mask_free(mask_set);

    if (stack->size == key_set_size)
        return stack;
    _xorf_list_free(stack);
    return NULL;
}

uint64_t *_xorf_fingerprint_init(_xorf_list_t *stack, size_t *hash_seed)
{
    size_t capacity = (stack->size * 1.23 + 32) / 3;
    uint64_t *fingerprint = malloc(3 * capacity * sizeof(uint64_t));
    memset(fingerprint, 0, 3 * capacity * sizeof(uint64_t));
    while (stack->size) {
        size_t index = stack->head->index;
        uint64_t hash = stack->head->mask;
        uint64_t h0 = _xorf_hash_index(hash, hash_seed, 0, capacity);
        uint64_t h1 = _xorf_hash_index(hash, hash_seed, 1, capacity);
        uint64_t h2 = _xorf_hash_index(hash, hash_seed, 2, capacity);
        fingerprint[index] =
            hash ^ fingerprint[h0] ^ fingerprint[h1] ^ fingerprint[h2];
        _xorf_list_remove_head(stack);
    }
    return fingerprint;
}

/* Internal Hash Set functions for set in mapping step */
_xorf_hash_mask_t *_xorf_mask_new(size_t capacity)
{
    _xorf_hash_mask_t *mask = calloc(capacity + 1, sizeof(_xorf_hash_mask_t));
    for (size_t i = 0; i <= capacity; i++) {
        mask[i].count = mask[i].mask = 0;
    }
    return mask;
}

void _xorf_mask_free(_xorf_hash_mask_t *mask)
{
    if (mask)
        free(mask);
}

void _xorf_hash_set_init(char **key_set,
                         size_t key_set_size,
                         _xorf_hash_mask_t *mask_set,
                         size_t *hash_seed,
                         size_t capacity)
{
    for (size_t i = 0; i < key_set_size; i++) {
        uint64_t hash = _xorf_djb2_hash_64(key_set[i]);
        uint64_t h0 = _xorf_hash_index(hash, hash_seed, 0, capacity / 3);
        uint64_t h1 = _xorf_hash_index(hash, hash_seed, 1, capacity / 3);
        uint64_t h2 = _xorf_hash_index(hash, hash_seed, 2, capacity / 3);
        mask_set[h0].mask ^= hash;
        mask_set[h0].count++;
        mask_set[h1].mask ^= hash;
        mask_set[h1].count++;
        mask_set[h2].mask ^= hash;
        mask_set[h2].count++;
    }
}

long _xorf_hash_set_scan(_xorf_hash_mask_t *mask_set, size_t capacity)
{
    for (long i = 0; i < capacity; i++)
        if (mask_set[i].count == 1)
            return i;
    return -1;
}

/* The implementations of internal list functions for construction */

/*
 * Initialize a new list
 */
_xorf_list_t *_xorf_list_new()
{
    _xorf_list_t *l = malloc(sizeof(_xorf_list_t));
    if (!l)
        return NULL;
    l->head = l->tail = NULL;
    l->size = 0;
    return l;
}

/*
 * Free all storage used by list l
 */
void _xorf_list_free(_xorf_list_t *l)
{
    if (!l)
        return;

    while (l->head) {
        _xorf_list_element_t *prev = l->head;
        l->head = l->head->next;
        _xorf_list_element_free(prev);
    }
    /* Free list structure */
    free(l);
}

/*
 * Insert a new element at the head of list
 */
bool _xorf_list_insert_head(_xorf_list_t *l, size_t index, uint64_t mask)
{
    if (!l)
        return false;
    _xorf_list_element_t *new_element = _xorf_list_element_new(index, mask);
    if (!new_element)
        return false;
    new_element->next = l->head;
    if (l->head == NULL)
        l->tail = new_element;
    l->head = new_element;
    l->size++;
    return true;
}

/*
 * Remove the head element of list;
 */
bool _xorf_list_remove_head(_xorf_list_t *l)
{
    if (!l || !l->head)
        return false;

    _xorf_list_element_t *element = l->head;
    l->head = l->head->next;
    l->size--;
    _xorf_list_element_free(element);
    return true;
}

/*
 * Return number of elements in the list
 */
size_t _xorf_list_size(_xorf_list_t *l)
{
    if (!l)
        return 0;
    return l->size;
}

/* The implementations of internal list element functions for list*/

/*
 * Initialize a new list element
 */
_xorf_list_element_t *_xorf_list_element_new(size_t index, uint64_t mask)
{
    _xorf_list_element_t *new_element = malloc(sizeof(_xorf_list_element_t));
    if (!new_element)
        return NULL;
    new_element->mask = mask;
    new_element->index = index;
    new_element->next = NULL;
    return new_element;
}

/*
 * Free all storage used by list element e
 */
void _xorf_list_element_free(_xorf_list_element_t *e)
{
    free(e);
}