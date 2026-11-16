#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h> 
#include <netinet/in.h>
#include <sys/socket.h>
#include "hash_table.h"
#include <stdbool.h>

#define MAX_FILES 67 

typedef struct {
    char *items[MAX_FILES];
    uint8_t count;
} zone_files;

typedef struct {
    char *items[MAX_FILES];
    uint8_t count;
} block_lists;

typedef struct {
    uint16_t timeout;
    uint16_t port;
    char *DOH_URL;
    struct sockaddr_storage ip_addr; 
    hash_table *h_table; 
    zone_files zone_file;
    block_lists block_list; 
    bool insecure;
    bool default_address;
} config_type; 


void config_init(config_type *config); 


#endif