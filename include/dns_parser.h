#include <stdbool.h>


enum parse_state {
    PARSE_OK,
    PARSE_DROP,
    PARSE_NOTIMP,
    PARSE_FORMERR,
    PARSE_REFUSED
}; 

struct dns_header { 
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
};


struct reader {
    const uint8_t *buffer;
    size_t len;
    size_t position;
};

typedef struct reader reader;
typedef struct dns_header dns_header;


void read_u32(reader *rdr, uint16_t *out);
bool read_u16(reader *rdr, uint16_t *out);
void read_u8(reader *rdr, uint8_t *out);

uint16_t get_u16(const uint8_t *buff);
uint8_t get_u8(const uint8_t *buff);
uint32_t get_u32(const uint8_t *buff);