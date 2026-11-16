#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "event_loop.h"
#include "dns_parser.h"
#include "dns_response.h"
#include "doh_forward.h"
#include "query_log.h"

#define MAX_LISTENERS 4
#define MAX_TCP_CONN 64
#define TCP_IDLE_MS 10000
#define POLL_TIMEOUT_MS 1000
#define UDP_BATCH 64

typedef struct tcp_conn {
    bool used;
    int fd;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    uint8_t buf[2 + 65535];      
    size_t len;
    long long last_activity;
    int pending;              
} tcp_conn_type;

typedef struct client_ctx {
    bool used;
    bool tcp;
    int fd;                    
    tcp_conn_type *conn;         
    struct sockaddr_storage addr;
    socklen_t addr_len;
    dns_query query;
    uint8_t msg[12 + 260];       
} client_ctx_type;

static tcp_conn_type conns[MAX_TCP_CONN];
static client_ctx_type ctxs[DOH_MAX_PENDING];
static volatile sig_atomic_t stop_requested = 0;
static config_type *cfg;
static zones *zone_list;

static void on_signal(int sig) {
    (void)sig;
    stop_requested = 1;
}

static long long now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool send_response(int fd, bool tcp, const struct sockaddr_storage *addr, socklen_t addr_len,
                          const uint8_t *resp, size_t len) {
    if(!tcp) {
        sendto(fd, resp, len, 0, (const struct sockaddr *)addr, addr_len);
        return true;
    }
    static uint8_t frame[2 + 65535];
    frame[0] = (uint8_t)(len >> 8);
    frame[1] = (uint8_t)(len & 0xFF);
    memcpy(frame + 2, resp, len);

    size_t sent = 0;
    while(sent < len + 2) {
        ssize_t n = send(fd, frame + sent, len + 2 - sent, MSG_NOSIGNAL);
        if(n < 0) {
            return false;
        }
        sent += (size_t)n;
    }
    return true;
}


static size_t udp_truncate(uint8_t *resp, size_t len, const dns_query *q) {
    if(len <= udp_limit(q)) {
        return len;
    }

    reader rdr = {.buffer = resp, .len = len, .position = 12};
    dns_record rcd;
    bool root;
    dns_skip_name(&rdr, &root);
    dns_skip_bytes(&rdr, 4);
    size_t question_end = rdr.position;


    size_t opt_start = 0;
    size_t opt_len = 0;
    uint16_t an = get_u16(resp + 6);
    uint16_t ns = get_u16(resp + 8);
    uint16_t ar = get_u16(resp + 10);
    bool ok = true;
    for(uint32_t i = 0; ok && i < (uint32_t)an + ns; i++) {
        ok = dns_skip_rr(&rdr, &rcd);
    }
    for(uint16_t i = 0; ok && i < ar; i++) {
        size_t start = rdr.position;
        ok = dns_skip_rr(&rdr, &rcd);
        if(ok && rcd.type == DNS_TYPE_OPT) {
            opt_start = start;
            opt_len = rdr.position - start;
        }
    }

    resp[2] |= 0x02;                     
    memset(resp + 6, 0, 6);                 
    size_t out = question_end;
    if(q->has_opt) {
        if(opt_len > 0) {
            memmove(resp + out, resp + opt_start, opt_len);
            out += opt_len;
        } else {
            static const uint8_t bare_opt[11] = {0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0};
            memcpy(resp + out, bare_opt, sizeof(bare_opt));
            out += sizeof(bare_opt);
        }
        resp[11] = 1;
    }
    return out;
}

static bool is_blocked(const char *name) {
    if(cfg->h_table == NULL) {
        return false;
    }
    const char *p = name;
    while(p != NULL) {
        if(htable_find_element(cfg->h_table, p, NULL)) {
            return true;
        }
        p = strchr(p, '.');
        if(p != NULL) {
            p++;
        }
    }
    return false;
}

static void close_conn(tcp_conn_type *conn) {
  
    for(int i = 0; i < DOH_MAX_PENDING; i++) {
        if(ctxs[i].used && ctxs[i].conn == conn) {
            ctxs[i].conn = NULL;
        }
    }
    close(conn->fd);
    conn->used = false;
    conn->len = 0;
    conn->pending = 0;
}

static void on_doh_done(void *ctx, const uint8_t *resp, size_t len) {
    client_ctx_type *c = ctx;
    static uint8_t out[DNS_MAX_MESSAGE];
    size_t out_len;
    int rcode;

    if(resp != NULL) {
        memcpy(out, resp, len);
        out_len = len;
        if(!c->tcp) {
            out_len = udp_truncate(out, out_len, &c->query);
        }
        rcode = out[3] & 0x0F;
    } else {
        out_len = dns_build_simple(&c->query, c->msg, DNS_RCODE_SERVFAIL, out, sizeof(out));
        rcode = DNS_RCODE_SERVFAIL;
    }

    tcp_conn_type *conn = c->conn;
    bool sent_ok = true;
    if(!c->tcp) {
        send_response(c->fd, false, &c->addr, c->addr_len, out, out_len);
    } else if(conn != NULL) {
        sent_ok = send_response(conn->fd, true, &c->addr, c->addr_len, out, out_len);
    }
    query_log(&c->addr, c->msg, true, c->query.qst.type, "forwarded", rcode);
    c->used = false;

    if(conn != NULL) {
        conn->pending--;
        conn->last_activity = now_ms();
        if(!sent_ok) {
            close_conn(conn);
        }
    }
}

static bool handle_message(const uint8_t *msg, size_t len, int fd, tcp_conn_type *conn,
                           const struct sockaddr_storage *addr, socklen_t addr_len) {
    static uint8_t resp[DNS_MAX_MESSAGE];
    size_t resp_len = 0;
    bool tcp = conn != NULL;
    dns_query q;
    enum parse_result pr = dns_parser(msg, len, &q);

    if(pr == PARSE_DROP) {
        query_log(addr, msg, false, 0, "dropped", RCODE_NONE);
        return false;
    }

    if(pr != PARSE_OK) {
        uint8_t rcode = DNS_RCODE_REFUSED;
        if(pr == PARSE_FORMERR) {
            rcode = DNS_RCODE_FORMERR;
        } else if(pr == PARSE_NOTIMP) {
            rcode = DNS_RCODE_NOTIMP;
        }
        resp_len = dns_build_simple(&q, msg, rcode, resp, sizeof(resp));
        bool ok = send_response(fd, tcp, addr, addr_len, resp, resp_len);
        query_log(addr, msg, q.parsed_question, q.qst.type, "invalid", rcode);
        return ok;
    }

    if(zone_answer(zone_list, &q, msg, resp, &resp_len)) {
        if(!tcp) {
            resp_len = udp_truncate(resp, resp_len, &q);
        }
        bool ok = send_response(fd, tcp, addr, addr_len, resp, resp_len);
        query_log(addr, msg, true, q.qst.type, "local", resp[3] & 0x0F);
        return ok;
    }

    if(is_blocked(q.qst.domain)) {
        resp_len = dns_build_simple(&q, msg, DNS_RCODE_NXDOMAIN, resp, sizeof(resp));
        bool ok = send_response(fd, tcp, addr, addr_len, resp, resp_len);
        query_log(addr, msg, true, q.qst.type, "blocked", DNS_RCODE_NXDOMAIN);
        return ok;
    }

    client_ctx_type *c = NULL;
    for(int i = 0; i < DOH_MAX_PENDING; i++) {
        if(!ctxs[i].used) {
            c = &ctxs[i];
            break;
        }
    }
    if(c != NULL) {
        c->tcp = tcp;
        c->fd = fd;
        c->conn = conn;
        c->addr = *addr;
        c->addr_len = addr_len;
        c->query = q;
        memcpy(c->msg, msg, 12 + q.qst.wire_len);
        if(doh_submit(msg, len, c)) {
            c->used = true;
            if(conn != NULL) {
                conn->pending++;
            }
            return true;
        }
    }

    resp_len = dns_build_simple(&q, msg, DNS_RCODE_SERVFAIL, resp, sizeof(resp));
    bool ok = send_response(fd, tcp, addr, addr_len, resp, resp_len);
    query_log(addr, msg, true, q.qst.type, "forwarded", DNS_RCODE_SERVFAIL);
    return ok;
}

static void udp_read(int fd) {
    static uint8_t msg[65535];
    for(int i = 0; i < UDP_BATCH; i++) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        ssize_t n = recvfrom(fd, msg, sizeof(msg), 0, (struct sockaddr *)&addr, &addr_len);
        if(n < 0) {
            return;    
        }
        handle_message(msg, (size_t)n, fd, NULL, &addr, addr_len);
    }
}

static void tcp_accept(int fd) {
    while(1) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        int cfd = accept(fd, (struct sockaddr *)&addr, &addr_len);
        if(cfd < 0) {
            return;
        }
        tcp_conn_type *conn = NULL;
        for(int i = 0; i < MAX_TCP_CONN; i++) {
            if(!conns[i].used) {
                conn = &conns[i];
                break;
            }
        }
        if(conn == NULL) {
            close(cfd);
            continue;
        }
        fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL) | O_NONBLOCK);
        conn->used = true;
        conn->fd = cfd;
        conn->addr = addr;
        conn->addr_len = addr_len;
        conn->len = 0;
        conn->pending = 0;
        conn->last_activity = now_ms();
    }
}

static void tcp_read(tcp_conn_type *conn) {
    ssize_t n = recv(conn->fd, conn->buf + conn->len, sizeof(conn->buf) - conn->len, 0);
    if(n < 0 && errno == EAGAIN) {
        return;
    }
    if(n <= 0) {
      
        close_conn(conn);
        return;
    }
    conn->len += (size_t)n;
    conn->last_activity = now_ms();

    size_t off = 0;
    while(conn->len - off >= 2) {
        size_t msg_len = get_u16(conn->buf + off);
        if(conn->len - off < 2 + msg_len) {
            break;
        }
        bool keep = handle_message(conn->buf + off + 2, msg_len, conn->fd, conn, &conn->addr, conn->addr_len);
        off += 2 + msg_len;
        if(!keep) {
            close_conn(conn);
            return;
        }
    }
    memmove(conn->buf, conn->buf + off, conn->len - off);
    conn->len -= off;
}

int event_loop(listeners *list, config_type *config, zones *zn) {
    cfg = config;
    zone_list = zn;

    if(doh_init(cfg->DOH_URL, cfg->timeout, cfg->insecure, on_doh_done) != 0) {
        fprintf(stderr, "isa-dnsproxy: cannot initialise DoH client\n");
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    while(!stop_requested) {
        struct pollfd fds[MAX_LISTENERS + MAX_TCP_CONN];
        tcp_conn_type *fd_conn[MAX_LISTENERS + MAX_TCP_CONN];
        int nfds = 0;

        for(int i = 0; i < list->sockets_count; i++) {
            fds[nfds].fd = list->sockets[i].fd;
            fds[nfds].events = POLLIN;
            fd_conn[nfds] = NULL;
            nfds++;
        }
        for(int i = 0; i < MAX_TCP_CONN; i++) {
            if(conns[i].used) {
                fds[nfds].fd = conns[i].fd;
                fds[nfds].events = POLLIN;
                fd_conn[nfds] = &conns[i];
                nfds++;
            }
        }

        doh_poll(fds, nfds, POLL_TIMEOUT_MS);

        for(int i = 0; i < nfds; i++) {
            if(!(fds[i].revents & POLLIN)) {
                continue;
            }
            if(i < list->sockets_count) {
                if(list->sockets[i].protocol == TRANSPORT_UDP) {
                    udp_read(fds[i].fd);
                } else {
                    tcp_accept(fds[i].fd);
                }
            } else {

                tcp_conn_type *conn = fd_conn[i];
                if(conn->used && conn->fd == fds[i].fd) {
                    tcp_read(conn);
                }
            }
        }

        long long now = now_ms();
        for(int i = 0; i < MAX_TCP_CONN; i++) {
            if(conns[i].used && conns[i].pending == 0 && now - conns[i].last_activity >= TCP_IDLE_MS) {
                close_conn(&conns[i]);
            }
        }
    }

    doh_shutdown();
    for(int i = 0; i < MAX_TCP_CONN; i++) {
        if(conns[i].used) {
            close_conn(&conns[i]);
        }
    }
    doh_cleanup();
    return 0;
}