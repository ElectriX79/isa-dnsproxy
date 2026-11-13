#ifndef DNS_RESPONSE_H
#define DNS_RESPONSE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "dns_response.h"
#include "dns_parser.h"

#define DNS_RCODE_NOERROR   0
#define DNS_RCODE_FORMERR   1
#define DNS_RCODE_SERVFAIL  2
#define DNS_RCODE_NXDOMAIN  3
#define DNS_RCODE_NOTIMP    4
#define DNS_RCODE_REFUSED   5

#define DNS_UDP_MIN_LIMIT   512
#define DNS_UDP_MAX_LIMIT   1232
#define DNS_MAX_MESSAGE     65535

typedef struct writer {
    uint8_t *buffer;
    size_t cap;
    size_t position;
} writer;

/* UDP limit odpovede pre daný dotaz: 512 bez OPT, inak udp_size orezaná na 512..1232 */
size_t udp_limit(const dns_query *q);

size_t dns_build_simple(const dns_query *q, const uint8_t *msg, uint8_t rcode, uint8_t *out, size_t cap);

#endif /* DNS_RESPONSE_H */