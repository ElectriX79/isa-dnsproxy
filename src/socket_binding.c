#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sysexits.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "socket_binding.h"

static void format_addr(const struct sockaddr_storage *ss, char *buf, size_t size)
{
    char ip[INET6_ADDRSTRLEN];
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *a = (const void *)ss;
        snprintf(buf, size, "%s:%u", inet_ntop(AF_INET, &a->sin_addr, ip, sizeof ip), ntohs(a->sin_port));
    } else {
        const struct sockaddr_in6 *a = (const void *)ss;
        snprintf(buf, size, "[%s]:%u", inet_ntop(AF_INET6, &a->sin6_addr, ip, sizeof ip), ntohs(a->sin6_port));
    }
}

static int open_one(const listener *l)
{
    int one = 1;
    int tcp = (l->protocol == TRANSPORT_TCP);
    int fd = socket(l->family, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);

    if (fd < 0
        || (l->family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one) < 0)
        || (tcp && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) < 0)
        || bind(fd, (const struct sockaddr *)&l->addr, l->len) < 0
        || (tcp && listen(fd, SOMAXCONN) < 0)
        || fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0) {
        char where[INET6_ADDRSTRLEN + 16];
        format_addr(&l->addr, where, sizeof where);
        fprintf(stderr, "isa-dnsproxy: cannot open %s %s: %s\n", tcp ? "tcp" : "udp", where, strerror(errno));
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return fd;
}

int open_sockets(listeners *list, const config_type *cfg)
{
    struct sockaddr_storage addrs[2] = {0};
    int n = 1;

    if (cfg->default_address) {
        addrs[0] = cfg->ip_addr;
    } else {
        ((struct sockaddr_in *)&addrs[0])->sin_family = AF_INET;        
        ((struct sockaddr_in6 *)&addrs[1])->sin6_family = AF_INET6;        
        n = 2;
    }

    list->sockets_count = 0;
    for (int a = 0; a < n; a++) {
        int v4 = (addrs[a].ss_family == AF_INET);
        if (v4)
            ((struct sockaddr_in *)&addrs[a])->sin_port = htons(cfg->port);
        else
            ((struct sockaddr_in6 *)&addrs[a])->sin6_port = htons(cfg->port);

        for (int p = TRANSPORT_UDP; p <= TRANSPORT_TCP; p++) {
            listener *l = &list->sockets[list->sockets_count];
            l->protocol = p;
            l->family = addrs[a].ss_family;
            l->addr = addrs[a];
            l->len = v4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
            if ((l->fd = open_one(l)) < 0) {
                close_sockets(list);
                return EX_UNAVAILABLE;
            }
            list->sockets_count++;
        }
    }

    for (int i = 0; i < list->sockets_count; i++) {     
        char where[INET6_ADDRSTRLEN + 16];
        format_addr(&list->sockets[i].addr, where, sizeof where);
        fprintf(stderr, "listening on %s\n", where);
    }
    return 0;
}

void close_sockets(listeners *list)
{
    for (int i = 0; i < list->sockets_count; i++)
        close(list->sockets[i].fd);
    list->sockets_count = 0;
}