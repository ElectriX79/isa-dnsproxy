#include <string.h>

#include "dns_response.h"

void put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xFF);
}

bool write_u8(writer *w, uint8_t v) {
    if (1 > w->cap - w->position) {
        return false;
    }
    w->buffer[w->position] = v;
    w->position += 1;
    return true;
}
bool write_u16(writer *w, uint16_t v) {
    if (2 > w->cap - w->position) {
        return false;
    }
    put_u16(w->buffer + w->position, v);
    w->position += 2;
    return true;
}

bool write_u32(writer *w, uint32_t v) {
    if (4 > w->cap - w->position) {
        return false;
    }
    put_u32(w->buffer + w->position, v);
    w->position += 4;
    return true;
}
bool write_bytes(writer *w, const uint8_t *data, size_t n) {
    if (n > w->cap - w->position) {
        return false;
    }
    memcpy(w->buffer + w->position, data, n);
    w->position += n;
    return true;
}

bool patch_u16(writer *w, size_t offset, uint16_t v) {
    if (offset > w->position || 2 > w->position - offset) {
        return false;
    }
    put_u16(w->buffer + offset, v);
    return true;
}


#define DNS_OFFSET_ARCOUNT 10


static bool write_response_header(writer *w, const dns_query *q, uint8_t rcode, bool aa) {
    uint16_t flags = 0;
    flags |= (uint16_t)(1u << 15);                          /* QR */
    flags |= (uint16_t)((q->hdr.opcode & 0xF) << 11);        /* OPCODE */
    flags |= (uint16_t)((aa ? 1u : 0u) << 10);              /* AA */
    flags |= (uint16_t)((q->hdr.rd ? 1u : 0u) << 8);        /* RD */
    flags |= (uint16_t)(1u << 7);                           /* RA */
    flags |= (uint16_t)((q->hdr.cd ? 1u : 0u) << 4);        /* CD */
    flags |= (uint16_t)(rcode & 0xF);                       /* RCODE */

    return write_u16(w, q->hdr.id)
        && write_u16(w, flags)
        && write_u16(w, q->parsed_question ? 1 : 0)         /* QDCOUNT */
        && write_u16(w, 0)                                  /* ANCOUNT */
        && write_u16(w, 0)                                  /* NSCOUNT */
        && write_u16(w, 0);                                 /* ARCOUNT */
}

bool write_question(writer *w, const dns_query *q, const uint8_t *msg) {
    if (!q->parsed_question) {
        return true;
    }
    return write_bytes(w, msg + DNS_HEADER_LEN, q->qst.wire_len);
}

bool write_opt(writer *w) {
    return write_u8(w, 0)
        && write_u16(w, DNS_TYPE_OPT)
        && write_u16(w, DNS_UDP_MAX_LIMIT)
        && write_u32(w, 0)
        && write_u16(w, 0);
}

/* ---------- verejné funkcie ---------- */

size_t udp_limit(const dns_query *q) {
    if (!q->has_opt) {
        return DNS_UDP_MIN_LIMIT;
    }
    if (q->udp_size < DNS_UDP_MIN_LIMIT) {
        return DNS_UDP_MIN_LIMIT;
    }
    if (q->udp_size > DNS_UDP_MAX_LIMIT) {
        return DNS_UDP_MAX_LIMIT;
    }
    return q->udp_size;
}

size_t dns_build_simple(const dns_query *q, const uint8_t *msg, uint8_t rcode,
                        uint8_t *out, size_t cap) {
    writer w = { .buffer = out, .cap = cap, .position = 0 };

    if (!write_response_header(&w, q, rcode, false)) {
        return 0;
    }
    if (!write_question(&w, q, msg)) {
        return 0;
    }
    if (q->has_opt) {
        if (!write_opt(&w) || !patch_u16(&w, DNS_OFFSET_ARCOUNT, 1)) {
            return 0;
        }
    }
    return w.position;
}