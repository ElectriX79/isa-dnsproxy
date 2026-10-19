#ifndef ZONEFILE_PARSER_H
#define ZONEFILE_PARSER_H

#include <stdint.h> 
#include "hash_table.h"

struct record  {
    uint32_t ttl;
    uint16_t type;
    uint16_t rdlength;
    uint8_t *rdata;
    struct record *next; 
};

typedef struct record record;


typedef struct soa soa;

struct zone {
    hash_table *h_table;
    record *soa; 
    char *name;
    char *filename;
};

typedef struct zone zone;

struct zones {
    uint32_t count;
    zone *zones; 
};

typedef struct zones zones; 

typedef struct { 
    const char *filename;
    unsigned long line_no;
    char *origin;
    bool seen_record;
    uint32_t default_ttl;
    bool has_default_ttl;
    char *prev_owner;
} parse_state;

void insert_ancestors(zone *zn, char *owner);
int check_record_rules(record *rcd, parse_state *st, zone *zn, item *owner_item);
int store_record(record *rcd, parse_state *st, zone *zn, char *owner);
void name_to_wire(const char *domain, uint8_t **dst, uint16_t *len);
int parse_ns_cname(record *rcd, parse_state *st, char *data, const char *error);
int parse_data_A(record *rcd, parse_state *st, char *line);
int parse_data_NS(record *rcd, parse_state *st, char *data);
int parse_data_CNAME(record *rcd, parse_state *st, char *data);
int parse_data_SOA(record *rcd, parse_state *st, char *data);
int parse_data_MX(record *rcd, parse_state *st, char *data);
int parse_data_AAAA(record *rcd, parse_state *st, char *data);
int zonefile_parser(config_type *cfg, zones **out);


#endif 