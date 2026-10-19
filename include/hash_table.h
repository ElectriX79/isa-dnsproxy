#include <stdint.h>
#include <stdbool.h>

#ifndef HASH_TABLE_H 
#define HASH_TABLE_H

struct item {
    char *name;
    void *value;
    struct item *next_element; 
};

typedef struct item item; 

typedef struct {
    uint32_t records_count;
    uint32_t bucket_count;
    item **buckets;
} hash_table;


void htable_insert_element(hash_table *h_table, const char *name, item **h_item);
bool htable_find_element(hash_table *h_table, const char *name, item **h_item);
hash_table *hashtable_constructor(uint32_t size);
void hashtable_destructor(hash_table *h_table);
static uint32_t hash_fnv1a(const char *str);

#endif 