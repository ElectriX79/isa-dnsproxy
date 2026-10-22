#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>

#include "dns_parser.h"



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

bool dns_qname_read(dns_question *qst,reader *rdr) {
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
            qst->domain[index] = '\0';
            return true;
        }
        wire_len++;

        if(wire_len + byte + 1 > 255) {
            return false;
        }
        if(index > 0) {
            qst->domain[index++] = '.'; 
        }

        for(uint8_t i = 0; i < byte; i++) {
            uint8_t chr;
            if(!read_u8(rdr, &chr)) {
                return false;
            }
            qst->domain[index++] = (char)tolower(chr); 
            wire_len++;
        }
    }
    return false; 
    
}

bool dns_question_read()
