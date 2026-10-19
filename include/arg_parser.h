#ifndef ARG_PARSER_H
#define ARG_PARSER_H

#include <stdint.h>

void print_help(void);
int validate_url(const char *url);
uint16_t validate_port(char *port);
uint16_t validate_timeout(char *timeout);
int arg_parser(char *argv[], int argc, config_type *cfg);


#endif
