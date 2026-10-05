#ifndef BLOCKLIST_PARSER_H 
#define BLOCKLIST_PARSER_H

#include "config.h"
#include "hash_table.h"
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>


int blocklist_parser(config_type *cfg);
uint32_t count_records(FILE *subor);
int process_line(hash_table *h_table, char *line, ssize_t len, char *file, int current_line);
int validate_token(char *token, bool first_token, char *file, int current_line);


#endif
