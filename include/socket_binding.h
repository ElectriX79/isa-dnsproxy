#ifndef SOCKET_BINDING_H
#define SOCKET_BINDING_H
#include <sys/socket.h>
#include "config.h"


enum transport {
    TRANSPORT_UDP,
    TRANSPORT_TCP
};

struct listener {
    int fd;
    enum transport protocol;
    int family;
    struct sockaddr_storage addr;
    socklen_t len;
};
typedef struct listener listener;

struct listeners {
    listener sockets[4];
    int sockets_count;
};

typedef struct listeners listeners;


int  open_sockets(listeners *list, const config_type *cfg);
void close_sockets(listeners *list);

#endif