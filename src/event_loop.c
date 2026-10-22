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
#include "socket_binding.h"


