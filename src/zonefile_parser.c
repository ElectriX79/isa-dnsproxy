#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <sysexits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "config.h"
#include "hash_table.h"
#include "zonefile_parser.h"

#define ZP_OK 0
#define ZP_FAIL -1

#define INIT_HASH_SIZE 64

#define HOSTNAME_OK 0

#define EMPTY_ORIGIN -10
#define INVALID_ORIGIN -9
#define HOSTNAME_INVALID -8

/* Prototypes of functions used before their definition */
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
void store_unsupported_record(parse_state *st, zone *zn, char *owner);


int lookup_type(const char *type) {
    static const struct {
        const char *name;
        int value;
        bool supported;
    } types[] = {
        {"A", 1, true},
        {"NS", 2,true},
        {"CNAME", 5,true},
        {"SOA", 6, true},
        {"MX", 15, true},
        {"AAAA", 28, true},
        {"TXT", 16, false},
        {"SRV", 33, false},
        {"PTR", 12, false},
        {"CAA", 257, false}
    };

    int count = sizeof(types) / sizeof(types[0]);

    for (int i = 0; i < count; i++) {
        if (strcasecmp(type, types[i].name) == 0) {
            return types[i].value;
        }
    }

    return -1; // Neznámy typ
}


zones* zoneBuffer_allocation(uint32_t zones_cnt) {
    zones *zs = calloc(1, sizeof(zones));

    if(zs == NULL) {
        fprintf(stderr, "Allocation error\n");
        exit(1);
    }
    zs->count = zones_cnt;

    if(zones_cnt == 0) {
        return zs;
    }
    zs->zones = calloc(zones_cnt, sizeof(zone));
    if(zs->zones == NULL) {
        fprintf(stderr, "Allocation error\n");
        exit(1);
    }

    return zs;
}

FILE *check_zoneFile(char *file) {
    FILE *subor;

    subor = fopen(file, "r");
    if(subor == NULL) {
        fprintf(stderr, "%s:0: %s\n", file, strerror(errno));
        return NULL;
    }
    struct stat st;
    if(fstat(fileno(subor), &st) != 0) {
        fprintf(stderr, "%s:0: %s\n", file,strerror(errno));
        fclose(subor);
        return NULL;
    }
    if(!S_ISREG(st.st_mode)) {
        fprintf(stderr,"%s:0: Not a regular file\n", file);
        fclose(subor);
        return NULL;
    }

    return subor;
}

int read_next_token(char **text, char **output) {
    char *tmp_text = (*text);
    while(isspace((unsigned char)*tmp_text)) {
        tmp_text++;
    }
    int token_len = 0;

    char *start_ptr = tmp_text;
    while(!isspace((unsigned char)*tmp_text) && *tmp_text != '\0') {
        token_len++;
        tmp_text++;
    }
    if(token_len == 0) {
        return -1;
    }

    (*output) = calloc(token_len+1, sizeof(char));
    if(*output == NULL) {
        fprintf(stderr, "Allocation error\n");
        exit(1);
    }
    *text = tmp_text;
    char *store_start = (*output);
    for(int i = 0; i < token_len; i++) {
        *(*output) = (*start_ptr);
        (*output)++;
        start_ptr++;
    }
    *(*output) = '\0';
    *output = store_start;

    return token_len;
}

int normalize_validate_hostname(char *host_name) {
    int len = strlen(host_name);
    if(len == 0) {
        return HOSTNAME_INVALID;
    }
    if(host_name[len-1] == '.') {
        host_name[--len] = '\0';
    }
    if(len == 0 || len > 253) {
        return HOSTNAME_INVALID;
    }
    size_t label_len = 0;
    for (char *p = host_name; *p != '\0'; p++) {
        if (*p == '.') {
            if (label_len == 0) {
                return HOSTNAME_INVALID;
            }
            label_len = 0;
            continue;
        }
        if (++label_len > 63) {
            return HOSTNAME_INVALID;
        }
        *p = (char)tolower((unsigned char)*p);
    }

    if (label_len == 0) {
        return HOSTNAME_INVALID;
    }

    return HOSTNAME_OK;
}

bool prepare_line(char *line) {
    bool starts_with_space = isspace((unsigned char)(*line));
    char *semi = strchr(line, ';');
    if(semi != NULL) {
        *semi = '\0';
    }
    size_t len = strlen(line);
    while(len > 0 && isspace((unsigned char)line[len-1])) {
        line[--len] = '\0';
    }

    return starts_with_space;
}

void zp_error(const parse_state *st, const char *s) {
    fprintf(stderr, "%s:%lu: %s\n",st->filename, st->line_no, s);
}

int process_origin(parse_state *st, zone *zn , char *line) {
    char *name = NULL;
    char *extra = NULL;

    if(st->origin != NULL) {
        zp_error(st, "$ORIGIN may appear only once");
        return ZP_FAIL;
    }
    if(st->seen_record) {
        zp_error(st, "$ORIGIN must come before the first record");
        return ZP_FAIL;
    }
    if(read_next_token(&line, &name) == -1) {
        zp_error(st, "$ORIGIN requires a name");
        return ZP_FAIL;
    }
    if(read_next_token(&line, &extra) != -1) {
        zp_error(st, "unexpected token after $ORIGIN name");
        free(name), free(extra);
        return ZP_FAIL;
    }
    if(name[strlen(name)-1] != '.') {
        zp_error(st, "$ORIGIN name must be absolute");
        free(name);
        return ZP_FAIL;
    }
    if(normalize_validate_hostname(name) == HOSTNAME_INVALID) {
        zp_error(st, "$ORIGIN name is invalid");
        free(name);
        return ZP_FAIL;
    }
    zn->name = name;
    st->origin = name; // DONT FORGET TO FREE MEMORY (char*name);

    return ZP_OK;


}

int parse_ttl_u32(const char *s, uint32_t min, uint32_t max, uint32_t *ttl) {
    if(!isdigit((unsigned char)*s)) {
        return ZP_FAIL;
    }
    errno = 0;
    char *end_ptr;
    unsigned long long value = strtoull(s, &end_ptr, 10);
    if(errno == ERANGE || *end_ptr != '\0' || value < min || value > max) {
        return ZP_FAIL;
    }
    *ttl = (uint32_t)value;
    return ZP_OK;
}

int process_ttl(parse_state *st, char *line) {
    char *value = NULL;
    char *extra = NULL;
    uint32_t ttl;

    if(read_next_token(&line, &value) == -1) {
        zp_error(st, "$ttl value is required");
        return ZP_FAIL;
    }
    if(read_next_token(&line, &extra) != -1) {
        zp_error(st, "$ttl unexpected token after ttl value");
        free(value);
        free(extra);
        return ZP_FAIL;
    }
    if(parse_ttl_u32(value, 0, 2147483647u, &ttl) != ZP_OK) {
        zp_error(st, "invalid $ttl");
        free(value);
        return ZP_FAIL;
    }
    free(value);
    st->default_ttl = ttl;
    st->has_default_ttl = true;
    return ZP_OK;
}

int process_directive(parse_state *st, zone *zn, char *line) {
    char *name = NULL;
    int ret_val;

    read_next_token(&line, &name);

    if(strcasecmp(name, "$origin") == 0) {
        ret_val = process_origin(st, zn, line);
    }
    else if(strcasecmp(name, "$ttl") == 0) {
        ret_val = process_ttl(st, line);
    }
    else {
        zp_error(st, "unsupported directive");
        ret_val = ZP_FAIL;
    }

    free(name);
    return ret_val;
}

int make_name(parse_state *st, char *token ,char **output) {
    char *owner;
    size_t t_len = strlen(token);
    if(strcasecmp(token, "@") == 0) {
        if(st->origin == NULL) {
            zp_error(st, "@ used before $origin");
            return ZP_FAIL;
        }
        owner = strdup(st->origin);
        if(owner == NULL) {
            fprintf(stderr, "Allocation error\n");
            exit(1);
        }
    }
    else if(*(token + t_len -1) == '.') {
        owner = strdup(token);
        if(owner == NULL) {
             fprintf(stderr, "Allocation error\n");
             exit(1);
        }
    }
    else {
        if(st->origin == NULL) {
            zp_error(st, "relative name used before origin");
            return ZP_FAIL;
        }

        owner = malloc(strlen(token) + strlen(st->origin) + 2);
        if(owner == NULL) {
            fprintf(stderr, "Allocation error\n");
            exit(1);
        }
        sprintf(owner, "%s.%s", token, st->origin);
    }
    if(normalize_validate_hostname(owner) == HOSTNAME_INVALID) {
        zp_error(st, "invalid domain name");
        free(owner);
        return ZP_FAIL;
    }
    (*output) = owner;

    return ZP_OK;
}

/* owner is the apex or lies below it on a label boundary */
static bool is_in_zone(const char *owner, const char *origin) {
    size_t olen = strlen(owner);
    size_t zlen = strlen(origin);
    if(olen == zlen) {
        return strcmp(owner, origin) == 0;
    }
    return olen > zlen
        && owner[olen - zlen - 1] == '.'
        && strcmp(owner + olen - zlen, origin) == 0;
}

int handle_record(parse_state *st, zone *zn, char *line, bool starts_with_space) {
    int ret_val = ZP_FAIL;
    char *owner = NULL;
    char *token = NULL;
    record *rcd = NULL;
    bool has_ttl = false;

    // Handling owner

    if(starts_with_space) {
        if(st->prev_owner == NULL) {
            zp_error(st, "first record has no owner");
            goto cleanup;
        }
        owner = strdup(st->prev_owner);
        if(owner == NULL) {
            fprintf(stderr, "Allocation error\n");
            exit(1);
        }
    }
    else {
        read_next_token(&line, &token);

        if(make_name(st, token, &owner) == ZP_FAIL) {
            goto cleanup;
        }
        free(token);
        token = NULL;
    }

    if(read_next_token(&line, &token) == -1) {
        zp_error(st, "Incomplete record");
        goto cleanup;
    }

    uint32_t ttl = 0;
    if(parse_ttl_u32(token, 0, 2147483647u,&ttl) == ZP_OK) {
        has_ttl = true;
        free(token);
        token = NULL;
        if(read_next_token(&line, &token) == -1) {
            zp_error(st, "Incomplete record");
            goto cleanup;
        }
    }
    if(strcasecmp(token, "in") == 0) {
        free(token);
        token = NULL;
        if(read_next_token(&line, &token) == -1) {
            zp_error(st, "Incomplete record");
            goto cleanup;
        }
    }

    /* TODO: registered but unsupported type (TXT, SRV, ...) -> warning,
       owner + ancestors still exist; only an unregistered type is an error */
    int type = lookup_type(token);
    if(type == -1) {
        zp_error(st, "unsupported type");
        goto cleanup;
    }
    if(!st->has_default_ttl && !has_ttl) {
        zp_error(st, "record doesnt have ttl");
        goto cleanup;
    }

    /* origin from the first SOA when there is no $ORIGIN */
    if(st->origin == NULL) {
        if(type != 6) {
            zp_error(st, "first record if origin not present must be SOA type");
            goto cleanup;
        }
        zn->name = strdup(owner);
        if(zn->name == NULL) {
            fprintf(stderr, "Allocation error\n");
            exit(1);
        }
        st->origin = zn->name;
    }
    if(type == 6) {
        if(strcmp(owner, st->origin) != 0) {
            zp_error(st, "SOA owner must be the zone origin");
            goto cleanup;
        }
        if(zn->soa != NULL) {
            zp_error(st, "zone must have exactly one SOA record");
            goto cleanup;
        }
    }
    if(!is_in_zone(owner, st->origin)) {
        zp_error(st, "owner is outside of the zone");
        goto cleanup;
    }

    rcd = calloc(1, sizeof *rcd);
    if(rcd == NULL) {
        fprintf(stderr, "Allocation error\n");
        exit(1);
    }

    if(has_ttl) {
        rcd->ttl = ttl;
    }
    else {
        rcd->ttl = st->default_ttl;
    }
    rcd->type = type;
    bool supported = false;
    switch(type) {
        case 1:
            if(parse_data_A(rcd, st, line) == ZP_FAIL) {
                goto cleanup;
            }
            if(store_record(rcd, st,zn, owner) == ZP_FAIL) {
                goto cleanup;
            }
            break;
        case 2:
            if(parse_data_NS(rcd, st, line) == ZP_FAIL) {
                goto cleanup;
            }
            if(store_record(rcd, st,zn, owner) == ZP_FAIL) {
                goto cleanup;
            }
            break;
        case 5:
            if(parse_data_CNAME(rcd, st, line) == ZP_FAIL) {
                goto cleanup;
            }
            if(store_record(rcd, st,zn, owner) == ZP_FAIL) {
                goto cleanup;
            }
            break;
        case 6:
            if(parse_data_SOA(rcd, st, line) == ZP_FAIL) {
                goto cleanup;
            }
            if(store_record(rcd, st,zn, owner) == ZP_FAIL) {
                goto cleanup;
            }
            zn->soa = rcd;
            break;
        case 15:
            if(parse_data_MX(rcd, st, line) == ZP_FAIL) {
                goto cleanup;
            }
            if(store_record(rcd, st,zn, owner) == ZP_FAIL) {
                goto cleanup;
            }
            break;
        case 28:
            if(parse_data_AAAA(rcd, st, line) == ZP_FAIL) {
                goto cleanup;
            }
            if(store_record(rcd, st,zn, owner) == ZP_FAIL) {
                goto cleanup;
            }
            break;
        case 16:
            zp_error(st, "warning, unsupported type: txt");
            store_unsupported_record(st, zn, owner);
            break;
        case 12:
            zp_error(st, "warning, unsupported type: ptr");
            store_unsupported_record(st, zn, owner);
            break;
        case 33:
            zp_error(st, "warning, unsupported type: srv");
            store_unsupported_record(st, zn, owner);
            break;
        case 257:
            zp_error(st, "warning, unsupported type: caa");
            store_unsupported_record(st, zn, owner);
            break;
    }
    rcd = NULL;

    insert_ancestors(zn, owner);
    st->seen_record = true;
    free(st->prev_owner);
    st->prev_owner = owner;
    owner = NULL;                   /* owned by st now */
    ret_val = ZP_OK;

cleanup:
    free(token);
    free(owner);
    if(rcd != NULL) {
        free(rcd->rdata);
        free(rcd);
    }
    return ret_val;
}

void insert_ancestors(zone *zn, char *owner) {
    char *ptr = NULL;
    hash_table *h_table = zn->h_table;
    if(strcmp(owner, zn->name) == 0) {
        return;
    }
    while(((ptr = strchr(owner, '.')) != NULL) &&  strcmp(ptr+1, zn->name) != 0){
        if(htable_find_element(h_table, ptr+1, NULL) == true) {
            break;
        }
        htable_insert_element(h_table, ptr+1, NULL);
        owner = ptr+1;
    }
}


int check_record_rules(record *rcd, parse_state *st, zone *zn, item *owner_item) {
    (void)zn;
    bool is_cname = (rcd->type == 5);
    for(record *r = owner_item->value; r!= NULL; r = r->next) {
        if(is_cname) {
            zp_error(st, "owner who has cname record cannot have more records");
            return ZP_FAIL;
        }

        if(r->type == rcd->type && r->rdlength == rcd-> rdlength && memcmp(r->rdata, rcd->rdata, rcd->rdlength) == 0) {
            zp_error(st, "duplicit record not allowed");
            return ZP_FAIL;
        }

        if(r->type == 5) {
            zp_error(st, "cname cannot coexists with other records");
            return ZP_FAIL;
        }
        if(r->type == rcd->type && r->ttl != rcd-> ttl) {
            zp_error(st, "record with given type cannot have different ttls");
            return ZP_FAIL;
        }
    }
    return ZP_OK;

}

void store_unsupported_record(parse_state *st, zone *zn, char *owner) {
    hash_table *h_table = zn->h_table;
    if(htable_find_element(h_table, owner, NULL) == false) {
        htable_insert_element(h_table, owner, NULL);
    }
}

int store_record(record *rcd, parse_state *st, zone *zn, char *owner) {
    hash_table *h_table = zn->h_table;
    bool first_element = false;
    item *bucket = NULL;
    if(htable_find_element(h_table, owner, &bucket) == false) {
        htable_insert_element(h_table, owner, &bucket);
        first_element = true;
    }
    if(bucket == NULL) {
        return ZP_FAIL;
    }
    if(check_record_rules(rcd, st, zn, bucket) == ZP_FAIL) {
        return ZP_FAIL;
    }
    if(first_element) {
        bucket->value = rcd;
        rcd->next = NULL;
    }
    else {
        rcd->next = bucket->value;
        bucket->value = rcd;
    }
    return ZP_OK;


}

void name_to_wire(const char *domain, uint8_t **dst, uint16_t *len) {
    uint8_t *buffer = malloc(256);
    if(buffer == NULL) {
        fprintf(stderr, "allocation error\n");
        exit(1);
    }
    uint16_t len_t = strlen(domain);
    uint16_t label_len = 0;

    for(uint16_t i = 0; i < len_t; i++) {
        if(domain[i] == '.') {
            buffer[i-label_len] = (uint8_t)label_len;
            label_len = 0;
            continue;
        }
        buffer[i+1] = domain[i];
        label_len++;
    }
    if(label_len != 0) {
        buffer[len_t-label_len] = (uint8_t)label_len;
    }
    buffer[len_t+1] = 0;
    *len = len_t + 2;
    (*dst) = buffer;

}

int parse_ns_cname(record *rcd, parse_state *st, char *data, const char *error) {
    char *token;
    char *check;
    char *target;

    if(read_next_token(&data, &token) == -1) {
        zp_error(st, error);
        return ZP_FAIL;
    }

    if(read_next_token(&data, &check) != -1) {
        free(token);
        free(check);
        zp_error(st, "unexpected token after domain name");
        return ZP_FAIL;
    }

    if(make_name(st, token, &target) == ZP_FAIL) {
        free(token);
        return ZP_FAIL;
    }

    uint8_t *result;
    uint16_t rdata_len = 0;
    name_to_wire(target, &result, &rdata_len);
    rcd->rdlength = rdata_len;
    rcd->rdata = result;
    free(token);
    free(target);

    return ZP_OK;

}

int parse_data_A(record *rcd, parse_state *st, char *line) {
    char *addr = NULL;
    char *check = NULL;
    uint8_t buf[4];

    if(read_next_token(&line, &addr) == -1) {
        zp_error(st, "Missing ipv4 address in A type of record");
        return ZP_FAIL;
    }
    if(inet_pton(AF_INET, addr, buf) != 1) {
        zp_error(st, "Invalid address");
        free(addr);
        return ZP_FAIL;
    }
    free(addr);

    if(read_next_token(&line, &check) != -1) {
        zp_error(st, "unsupported token after IPv4 address");
        free(check);
        return ZP_FAIL;
    }

    rcd->rdata = malloc(4);
    if(rcd->rdata == NULL) {
        fprintf(stderr, "Allocation error\n");
        exit(1);
    }
    memcpy(rcd->rdata, buf, 4);
    rcd->rdlength = 4;
    return ZP_OK;

}

int parse_data_NS(record *rcd, parse_state *st, char *data) {
    if(parse_ns_cname(rcd, st, data, "missing domain name in NS record") == ZP_FAIL) {
        return ZP_FAIL;
    }
    return ZP_OK;
}

int parse_data_CNAME(record *rcd, parse_state *st, char *data) {
    if(parse_ns_cname(rcd, st, data, "missing domain name in CNAME record") == ZP_FAIL) {
        return ZP_FAIL;
    }
    return ZP_OK;
}

/* Reads one name from rdata: token -> make_name. *out is malloc'd. */
static int soa_read_name(parse_state *st, char **data, const char *missing_msg, char **out)
{
    char *token = NULL;

    if (read_next_token(data, &token) == -1) {
        zp_error(st, missing_msg);
        return ZP_FAIL;
    }
    int ret = make_name(st, token, out);      /* prints its own error */
    free(token);
    return ret;
}

/* Reads one number from rdata in [0, max]. */
static int soa_read_u32(parse_state *st, char **data, uint32_t max, uint32_t *out)
{
    char *token = NULL;

    if (read_next_token(data, &token) == -1) {
        zp_error(st, "SOA: missing number (serial refresh retry expire minimum)");
        return ZP_FAIL;
    }
    if (parse_ttl_u32(token, 0, max, out) != ZP_OK) {
        zp_error(st, "SOA: invalid number");
        free(token);
        return ZP_FAIL;
    }
    free(token);
    return ZP_OK;
}

int parse_data_SOA(record *rcd, parse_state *st, char *data)
{
    int ret = ZP_FAIL;
    char *mname = NULL, *rname = NULL, *extra = NULL;
    uint8_t *mwire = NULL, *rwire = NULL;
    uint16_t mlen = 0, rlen = 0;
    uint32_t nums[5];
    uint8_t buf[2 * 255 + 20];


    if (soa_read_name(st, &data, "SOA: missing mname", &mname) != ZP_OK)
        goto cleanup;
    if (soa_read_name(st, &data, "SOA: missing rname", &rname) != ZP_OK)
        goto cleanup;


    for (int i = 0; i < 5; i++) {
        uint32_t max = (i == 4) ? 2147483647u : 4294967295u;
        if (soa_read_u32(st, &data, max, &nums[i]) != ZP_OK)
            goto cleanup;
    }

    if (read_next_token(&data, &extra) != -1) {
        zp_error(st, "SOA: unexpected token after minimum");
        goto cleanup;
    }

    name_to_wire(mname, &mwire, &mlen);
    name_to_wire(rname, &rwire, &rlen);

    size_t pos = 0;
    memcpy(buf + pos, mwire, mlen);
    pos += mlen;
    memcpy(buf + pos, rwire, rlen);
    pos += rlen;
    for (int i = 0; i < 5; i++) {
        uint32_t be = htonl(nums[i]);
        memcpy(buf + pos, &be, 4);
        pos += 4;
    }

    rcd->rdata = malloc(pos);
    if (rcd->rdata == NULL) {
        zp_error(st, "Allocation error");
        goto cleanup;
    }
    memcpy(rcd->rdata, buf, pos);
    rcd->rdlength = (uint16_t)pos;
    ret = ZP_OK;

cleanup:
    free(mname);
    free(rname);
    free(extra);
    free(mwire);
    free(rwire);
    return ret;
}

int parse_data_MX(record *rcd, parse_state *st, char *data) {
    char *preference;
    uint32_t pref;
    char *exchange;
    char *check;
    if(read_next_token(&data, &preference) == -1) {
        zp_error(st, "missing preference");
        return ZP_FAIL;
    }
    if(parse_ttl_u32(preference, 0, 65535, &pref) == ZP_FAIL) {
        zp_error(st, "invalid preference");
        free(preference);
        return ZP_FAIL;
    }
    if(read_next_token(&data, &exchange) == -1) {
        zp_error(st, "missing mail domain");
        free(preference);
        return ZP_FAIL;
    }
    char *processed_exchange;
    if(make_name(st, exchange, &processed_exchange) == ZP_FAIL) {
        free(exchange);
        free(preference);
        return ZP_FAIL;
    }
    if(read_next_token(&data, &check) != -1) {
        zp_error(st, "unsupported token after mail domain");
        free(preference);
        free(exchange);
        free(processed_exchange);
        free(check);
        return ZP_FAIL;
    }
    free(preference);
    free(exchange);

    uint8_t *encoded_mail;
    uint16_t mail_len;
    name_to_wire(processed_exchange, &encoded_mail, &mail_len);
    uint8_t *ready_data = malloc(mail_len+2);

    if(!ready_data) {
        fprintf(stderr, "allocation error\n");
        exit(1);
    }

    ready_data[0] = (uint8_t)(pref >> 8);
    ready_data[1] = (uint8_t)pref;
    memcpy(ready_data+2, encoded_mail, mail_len);
    rcd->rdata = ready_data;
    rcd->rdlength = mail_len + 2;
    free(processed_exchange);
    free(encoded_mail);
    return ZP_OK;
}


int parse_data_AAAA(record *rcd, parse_state *st, char *data) {
    char *addr = NULL;
    char *check = NULL;
    uint8_t buf[16];

    if(read_next_token(&data, &addr) == -1) {
        zp_error(st, "missing IPv6 address in AAAA record");
        return ZP_FAIL;
    }
    if(inet_pton(AF_INET6, addr, buf) != 1) {
        zp_error(st, "invalid IPv6 address in AAAA record");
        free(addr);
        return ZP_FAIL;
    }
    free(addr);

    if(read_next_token(&data, &check) != -1) {
        zp_error(st, "unsupported token after IPv6 address");
        free(check);
        return ZP_FAIL;
    }

    rcd->rdata = malloc(16);
    if(rcd->rdata == NULL) {
        fprintf(stderr, "Allocation error\n");
        exit(1);
    }
    memcpy(rcd->rdata, buf, 16);
    rcd->rdlength = 16;

    return ZP_OK;
}



int process_record(parse_state *st, zone *zn, char *line) {
     bool starts_with_space = prepare_line(line);

     char *p = line;

     while(isspace((unsigned char)*p)) {
        p++;
     }
     if(*p == '\0') {
        return ZP_OK;
     }

     if(*p == '$') {
        return process_directive(st, zn, p);
     }
     if(handle_record(st, zn, p, starts_with_space) == ZP_FAIL) {
        return ZP_FAIL;
     }
     return ZP_OK;
}


int process_zone(FILE*file, zone *zn,  const char*filename) {
    parse_state st = {.filename = filename};
    char *line = NULL;
    size_t n = 0;
    int ret_val = ZP_OK;

    while(getline(&line, &n, file) != -1) {
        st.line_no++;
        if(process_record(&st, zn, line) != ZP_OK) {
            ret_val = ZP_FAIL;
            goto out;
        }
    }
    if(ferror(file)) {
        st.line_no = 0;
        zp_error(&st, strerror(errno));
        ret_val = ZP_FAIL;
        goto out;
    }
    if(zn->soa == NULL) {
        st.line_no = 0;
        zp_error(&st, "zone must have exactly one SOA record");
        ret_val = ZP_FAIL;
        goto out;
    }

out:
    free(line);
    free(st.prev_owner);
    fclose(file);
    return ret_val;
}

int zone_init(zone *zn, const char *filename) {
    hash_table *htable = hashtable_constructor((uint32_t)INIT_HASH_SIZE);
    if(htable == NULL) {
        fprintf(stderr, "Allocation error\n");
        exit(1);
    }
    zn->h_table = htable;
    zn->filename = filename;
    zn->soa = NULL;
    zn->name = NULL;

    return 0;

}

int zonefile_parser(config_type *cfg, zones **out) {
    zones *zs = zoneBuffer_allocation(cfg->zone_file.count);
    *out = zs;
    for(uint32_t zoneFiles_cnt = 0; zoneFiles_cnt < cfg->zone_file.count; zoneFiles_cnt++) {
        FILE *subor = check_zoneFile(cfg->zone_file.items[zoneFiles_cnt]);
        if(subor == NULL) {
            return EX_CONFIG;
        }
        if(zone_init(&zs->zones[zoneFiles_cnt], cfg->zone_file.items[zoneFiles_cnt]) != 0) {
            return EX_CONFIG;
        }

        if(process_zone(subor, &zs->zones[zoneFiles_cnt], cfg->zone_file.items[zoneFiles_cnt]) != ZP_OK) {
            return EX_CONFIG;
        }
    }
    return 0;
}