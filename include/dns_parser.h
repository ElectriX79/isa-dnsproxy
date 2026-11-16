#ifndef DNS_MESSAGE_H
#define DNS_MESSAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


#define DNS_HEADER_LEN  12

#define DNS_CLASS_IN    1

#define DNS_TYPE_SOA    6
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_OPT    41
#define DNS_TYPE_IXFR   251
#define DNS_TYPE_AXFR   252
#define DNS_TYPE_ANY    255


enum parse_result {
    PARSE_OK,
    PARSE_DROP,
    PARSE_NOTIMP,
    PARSE_FORMERR,
    PARSE_REFUSED
};


typedef struct dns_header {
    uint16_t id;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
    uint8_t rcode;
    uint8_t opcode;
    bool aa;
    bool tc;
    bool rd;
    bool ra;
    bool z;
    bool ad;
    bool cd;
    bool qr;
} dns_header;

typedef struct dns_question {
    char domain[256];
    uint16_t type;
    uint16_t qclass;
    size_t wire_len;
} dns_question;

typedef struct dns_record {
    uint16_t type;
    uint16_t rclass;
    bool is_root;
} dns_record;

typedef struct dns_query {
    dns_header hdr;
    dns_question qst;
    uint16_t udp_size;
    bool parsed_question;
    bool has_opt;
} dns_query;

typedef struct reader {
    const uint8_t *buffer;
    size_t len;
    size_t position;
} reader;

enum parse_result dns_parser(const uint8_t *msg, size_t len, dns_query *query);


uint8_t  get_u8(const uint8_t *buff);
uint16_t get_u16(const uint8_t *buff);
uint32_t get_u32(const uint8_t *buff);

bool read_u8(reader *rdr, uint8_t *out);
bool read_u16(reader *rdr, uint16_t *out);
bool read_u32(reader *rdr, uint32_t *out);
bool dns_skip_bytes(reader *rdr, size_t n);

bool dns_header_read(dns_header *hdr, reader *rdr);
enum parse_result validate_dns_header(dns_header *hdr);

bool dns_qname_read(dns_question *qst, reader *rdr);
bool dns_question_read(dns_question *dns_qst, reader *rdr);
enum parse_result validate_dns_question(dns_question *dns_qst);

bool dns_skip_name(reader *rdr, bool *is_root);
bool dns_skip_rr(reader *rdr, dns_record *dns_rcd);

#endif 