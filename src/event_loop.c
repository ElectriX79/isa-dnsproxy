#include <stdio.h>        // fprintf (ladiace výpisy, chyby)
#include <stdlib.h>       // malloc, free (TCP buffery)
#include <string.h>       // memset, memcpy, strerror
#include <errno.h>        // errno, EAGAIN, EWOULDBLOCK, EINTR
#include <stdint.h>       // uint8_t, uint16_t
#include <stdbool.h>      // bool

#include <unistd.h>       // close
#include <fcntl.h>        // fcntl, O_NONBLOCK (nastavenie pre sockety z accept)
#include <poll.h>         // poll, struct pollfd, POLLIN, POLLOUT, POLLERR, POLLHUP
#include <sys/types.h>    // ssize_t
#include <sys/socket.h>   // recvfrom, sendto, accept, recv, send, sockaddr_storage
#include <netinet/in.h>   // sockaddr_in, sockaddr_in6
#include <arpa/inet.h>    // inet_ntop (výpis adresy klienta), ntohs
#include "event_loop.h"
#include "dns_parser.h"
#include "dns_response.h"

#define MAX_LISTENERS 4

static uint8_t parse_result_to_rcode(enum parse_result r) {
    switch (r) {
    case PARSE_FORMERR: return DNS_RCODE_FORMERR;
    case PARSE_NOTIMP:  return DNS_RCODE_NOTIMP;
    case PARSE_REFUSED: return DNS_RCODE_REFUSED;
    default: return DNS_RCODE_SERVFAIL;   // PARSE_OK: dočasne, kým nie je forward
    }
}

int event_loop(listeners *list) {

    struct pollfd fds[MAX_LISTENERS];
    nfds_t nfds = 0;
    for(int i = 0; i < list->sockets_count; i++) {
        if(list->sockets[i].protocol == TRANSPORT_UDP) {
            fds[nfds].fd = list->sockets[i].fd;
            fds[nfds].events = POLLIN;
            nfds++;
        }
    }
    while(1) {
        int r = poll(fds, nfds, -1);
        if(r < 0) {
            if(errno == EINTR ) {
                continue;
            }
            perror("poll");
            return 1;
        }

        for(nfds_t i = 0; i < nfds; i++) {
            if(fds[i].revents & POLLIN) {
                static uint8_t msg[65535];
                struct sockaddr_storage client;
                socklen_t client_len = sizeof(client);
                ssize_t n = recvfrom(fds[i].fd, msg, sizeof msg, 0, (struct sockaddr *)&client,&client_len);

                if(n < 0) {
                    if(errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("recvfrom");

                    }
                    continue;
                }
                dns_query query;
                enum parse_result pr = dns_parser(msg, (size_t)n, &query);
                if(pr == PARSE_DROP) {
                    continue;
                }
                uint8_t rcode = parse_result_to_rcode(pr);



                static uint8_t resp[DNS_MAX_MESSAGE];

                size_t len = dns_build_simple(&query, msg, rcode, resp, sizeof(resp)); 
                if(len > 0) {
                    sendto(fds[i].fd, resp, len, 0, (struct sockaddr *)&client, client_len);
                }

            }
        }
    }
}

