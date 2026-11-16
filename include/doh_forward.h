#ifndef DOH_FORWARD_H
#define DOH_FORWARD_H

#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DOH_MAX_PENDING 64
#define DOH_MAX_FDS 1024

typedef struct pending pending_type;

typedef void (*doh_done_fn)(void *ctx, const uint8_t *resp, size_t resp_len);

int doh_init(const char *url, unsigned timeout, bool insecure, doh_done_fn done);
pending_type* doh_submit(const uint8_t *query, size_t query_len, void *ctx);
void doh_cancel(pending_type *req);
int doh_poll(struct pollfd *fds, int n, int timeout_ms);
void doh_shutdown();
void doh_cleanup();

#endif