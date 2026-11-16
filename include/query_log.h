#ifndef QUERY_LOG_H
#define QUERY_LOG_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#define RCODE_NONE -1   // dropped -> v logu "-"

void query_log(const struct sockaddr_storage *client, const uint8_t *msg, bool question_parsed, uint16_t qtype, const char *verdict, int rcode);

const char* dns_type_name(uint16_t type);

#endif