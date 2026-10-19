#include "../include/hash_table.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t hash_fnv1a(const char *str)
{
    uint32_t hash = 2166136261u;      
    for (const unsigned char *p = (const unsigned char *)str; *p != '\0'; p++) {
        hash ^= *p;
        hash *= 16777619u;      
    }
    return hash;
}

hash_table *hashtable_constructor(uint32_t size) {
    hash_table *h_table = calloc(1,sizeof(hash_table));
    if(h_table == NULL) {
        fprintf(stderr, "Allocation error\n");
        return NULL;
    }
    h_table->buckets = calloc(size, sizeof(item *));
    if(h_table->buckets == NULL) {
        fprintf(stderr, "Allocation error\n");
        return NULL;
    }
    h_table->bucket_count = size;
    return h_table;
}

void hashtable_destructor(hash_table *h_table) {
    if(h_table == NULL) {
        return;
    }
    for(uint32_t i = 0; i < h_table->bucket_count; i++) {
        if(h_table->buckets[i] != NULL) {
            item *bucket = h_table->buckets[i];
             for(item *node = bucket, *temp_node = NULL; node != NULL; node = temp_node) {
                temp_node = node->next_element;
                free(node->name);
                free(node);
             }
        }
    }
    free(h_table->buckets);
    free(h_table);
    return;
}

void htable_insert_element(hash_table *h_table, const char *name, item **h_item) {
    uint32_t hash_index = hash_fnv1a(name) % h_table->bucket_count;
    if(h_table->buckets[hash_index] == NULL) {
        item *node = calloc(1, sizeof(item));
        if(node == NULL) {
            fprintf(stderr, "Allocation error\n");
            exit(1);
        }
        node->name = calloc(strlen(name)+1, 1);
        if(node->name == NULL) {
            fprintf(stderr, "Allocation error\n");
            free(node);
            exit(1);
        }
        strcpy(node->name, name);
        node->next_element = NULL;
        h_table->buckets[hash_index] = node;
        h_table->records_count++;
        if(h_item != NULL) {
            (*h_item) = node; 
        }
    }
    else {
        item *node = calloc(1, sizeof(item));
        if(node == NULL) {
            fprintf(stderr,"Allocation error\n");
            exit(1);
        }
        node->name = calloc(strlen(name)+1, 1);
        if(node->name == NULL) {
            fprintf(stderr, "Allocation error\n");
            exit(1);
        }
        strcpy(node->name, name);
        node->next_element = h_table->buckets[hash_index];
        h_table->buckets[hash_index] = node;
        h_table->records_count++;
        if(h_item != NULL) {
            (*h_item) = node;
        }
    }
    return;
}

bool htable_find_element(hash_table *h_table, const char *name, item **h_item) {
    uint32_t hash_index = hash_fnv1a(name) % h_table->bucket_count;

    for(item *node = h_table->buckets[hash_index]; node != NULL; node = node->next_element) {
        if(strcmp(node->name, name) == 0) {
            if(h_item != NULL) {
                (*h_item) = node;
            }
            return true;
        }
    }
    
    return false;
}