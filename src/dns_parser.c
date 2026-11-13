#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>

#include "dns_parser.h"

#define DNS_CLASS_IN 1
#define DNS_TYPE_IXFR 251
#define DNS_TYPE_AXFR 252
#define DNS_TYPE_OPT 41

uint16_t get_u16(const uint8_t *buff) {
    uint16_t out;
    out = (((uint16_t)buff[0]) << 8);
    out |= buff[1];
    return out;
}

bool read_u16(reader *rdr, uint16_t *out) {
    const uint8_t *buffer = rdr->buffer;
    size_t len = rdr->len;
    size_t pos = rdr->position;

    if((pos + 2) > len) {
        return false;
    }

    *out = get_u16(buffer + pos);
    pos += 2;
    rdr->position = pos;

    return true;
}

uint8_t get_u8(const uint8_t *buff) {
    uint8_t out;
    out = buff[0];
    return out;
}

bool read_u8(reader *rdr, uint8_t *out) {
    const uint8_t *buffer = rdr->buffer;
    size_t len = rdr->len;
    size_t pos = rdr->position;

    if((pos + 1) > len) {
        return false;
    }

    *out = get_u8(buffer + pos);
    pos += 1;
    rdr->position = pos;
    return true;
}

uint32_t get_u32(const uint8_t *buff) {
    uint32_t out = 0;
    out |= (((uint32_t)buff[0]) << 24);
    out |= (((uint32_t)buff[1]) << 16);
    out |= (((uint32_t)buff[2]) << 8);
    out |= (((uint32_t)buff[3]));
    
    return out;
}

bool read_u32(reader *rdr, uint32_t *out) {
    const uint8_t *buffer = rdr->buffer;
    size_t len = rdr->len;
    size_t pos = rdr->position;

    if((pos + 4) > len) {
        return false;
    }

    *out = get_u32(buffer + pos);
    pos += 4;
    rdr->position = pos;
    return true;
}


void process_flags(uint16_t flags, dns_header *hdr) {
    hdr->qr = (flags >> 15) & 0x1;
    hdr->opcode = (flags >> 11) & 0xF;
    hdr->aa = (flags >> 10) & 0x1;
    hdr->tc = (flags >> 9)  & 0x1;
    hdr->rd = (flags >> 8)  & 0x1;
    hdr->ra = (flags >> 7)  & 0x1;
    hdr->z = (flags >> 6)  & 0x1;
    hdr->ad = (flags >> 5)  & 0x1;
    hdr->cd = (flags >> 4)  & 0x1;
    hdr->rcode =  flags & 0xF;
}

enum parse_result validate_dns_header(dns_header *hdr) {
    enum parse_result state = PARSE_OK;
    if(hdr->qr) {
        state = PARSE_DROP;

    } 
    else if(hdr->opcode) {
        state = PARSE_NOTIMP;

    }
    else if(hdr->qdcount != 1) {
        state = PARSE_FORMERR;
    }

    return state;
}

bool dns_header_read(dns_header *hdr ,reader *rdr) {

    uint16_t flags;
    if(!read_u16(rdr, &hdr->id) || !read_u16(rdr, &flags)) {
        return false;
    }
    process_flags(flags, hdr);

    if(!read_u16(rdr, &hdr->qdcount) || !read_u16(rdr, &hdr->ancount) || !read_u16(rdr, &hdr->nscount) || !read_u16(rdr, &hdr->arcount)) {
        return false;
    }
    return true;
}

bool dns_qname_read(dns_question *dns_qst,reader *rdr) {
    size_t index = 0;
    uint8_t byte;
    size_t wire_len = 0;

    while(wire_len < 256) {
        if(!read_u8(rdr, &byte)) {
            return false;
        }
        if(byte > 63) {
            return false; 
        }
        if(byte == 0) {
        dns_qst->domain[index] = '\0';
            return true;
        }
        wire_len++;

        if(wire_len + byte + 1 > 255) {
            return false;
        }
        if(index > 0) {
        dns_qst->domain[index++] = '.'; 
        }

        for(uint8_t i = 0; i < byte; i++) {
            uint8_t chr;
            if(!read_u8(rdr, &chr)) {
                return false;
            }
        dns_qst->domain[index++] = (char)tolower(chr); 
            wire_len++;
        }
    }
    return false; 
    
}



bool dns_question_read(dns_question *dns_qst, reader *rdr) {
    size_t start = rdr->position;

    if(dns_qname_read(dns_qst, rdr) == false) {
        return false;
    }
    uint16_t qtype;
    if(read_u16(rdr, &qtype) == false) {
        return false;
    }
    dns_qst->type = qtype;
    uint16_t class;
    if(read_u16(rdr, &class) == false) {
        return false;
    }
    size_t wire_len = rdr->position - start;
    dns_qst->wire_len = wire_len;
    dns_qst->qclass = class;
    return true;
}

enum parse_result validate_dns_question(dns_question *dns_qst) {
    enum parse_result prs_rst = PARSE_OK;
    if(dns_qst->qclass != DNS_CLASS_IN) {
        prs_rst = PARSE_NOTIMP;
    }
    else if(dns_qst->type == DNS_TYPE_AXFR ||dns_qst->type == DNS_TYPE_IXFR) {
        prs_rst = PARSE_REFUSED;
    }
    return prs_rst;
}


bool dns_skip_bytes(reader *rdr, size_t n) {
    if(n + rdr->position > rdr->len) {
        return false;
    }
    rdr->position+= n;
    return true;
}


bool dns_skip_name(reader *rdr, bool *is_root) {
    uint8_t byte;
    size_t wire_len = 0;
    (*is_root) = false;
    while(wire_len < 256) {
        if(read_u8(rdr, &byte) == false) {
            return false;
        }
        if(byte == 0) {
            if(wire_len == 0) {
                (*is_root) = true;
            }
            return true;
        }
        if(byte >= 192) {
            return dns_skip_bytes(rdr, 1);
        }
        if(byte > 63) {
            return false;
        }
        if(dns_skip_bytes(rdr, (size_t)byte) == false) {
            return false;
        }
        wire_len += (1 + byte);
    }
    return false;
}

bool dns_skip_rr(reader *rdr, dns_record *dns_rcd) {
    bool root;
    if(dns_skip_name(rdr, &root) == false) {
        return false;
    }
    dns_rcd->is_root = root;
    if(read_u16(rdr, &dns_rcd->type) == false) {
        return false;
    }
    if(read_u16(rdr, &dns_rcd->rclass) == false) {
        return false;
    }

    if(dns_skip_bytes(rdr, 4) == false) {
        return false;
    }
    uint16_t rdlength = 0;
    if(read_u16(rdr, &rdlength) == false) {
        return false;
    }
    if(dns_skip_bytes(rdr, rdlength) == false) {
        return false;
    }
    return true;
}



enum parse_result dns_parser(const uint8_t *msg, size_t len, dns_query *query) {
    dns_record rcd = {0};
    reader rdr = {.buffer = msg, .len = len, .position = 0};
    memset(query, 0, sizeof(*query)); 

    enum parse_result prs_rst = PARSE_OK;

    if(dns_header_read(&query->hdr, &rdr) == false) {
        prs_rst = PARSE_DROP;
        return prs_rst;
    }

    prs_rst = validate_dns_header(&query->hdr);
    if(prs_rst != PARSE_OK) {
        return prs_rst; 
    }

     if(dns_question_read(&query->qst, &rdr) == false) {
        prs_rst = PARSE_FORMERR;
        return prs_rst;
     }
     query->parsed_question = true;


     for(uint16_t i = 0; i < query->hdr.ancount; i++) {
        if(dns_skip_rr(&rdr, &rcd) == false) {
            prs_rst = PARSE_FORMERR;
            return prs_rst;
        }
        if(rcd.type == DNS_TYPE_OPT) {
            prs_rst = PARSE_FORMERR;
            return prs_rst;
        }
    }

    for(uint16_t i = 0; i < query->hdr.nscount; i++) {
        if(dns_skip_rr(&rdr, &rcd) == false) {
            prs_rst = PARSE_FORMERR;
            return prs_rst;
        }
        if(rcd.type == DNS_TYPE_OPT) {
            prs_rst = PARSE_FORMERR;
            return prs_rst;
        }
    }

    bool opt_seen = false;


    for(uint16_t i = 0; i < query->hdr.arcount;i++) {
        if(dns_skip_rr(&rdr, &rcd) == false) {
            prs_rst = PARSE_FORMERR;
            return prs_rst;
        }
        if(rcd.type == DNS_TYPE_OPT) {
            if(opt_seen) {
                prs_rst = PARSE_FORMERR;
                return prs_rst;
            }
            else if(!rcd.is_root) {
                prs_rst = PARSE_FORMERR;
                return prs_rst;
            }
            else {
                query->udp_size = rcd.rclass;
                opt_seen = true;
            }
        }
        else {
            continue;
        }
    }
    if(opt_seen) {
        query->has_opt = true;
    }
    prs_rst = validate_dns_question(&query->qst); 
    

    return prs_rst;

}
