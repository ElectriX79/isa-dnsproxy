#ifndef SOCKET_BINDING_H
#define SOCKET_BINDING_H
#include <sys/socket.h>


enum transport {
    TRANSPORT_UDP,
    TRANSPORT_TCP
};

struct listener {
    int socket_id;
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


int open_sockets(listeners *list, config_type *cfg);
int close_sockets(listeners *list);


#endif