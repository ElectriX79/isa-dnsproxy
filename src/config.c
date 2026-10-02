#include "./include/config.h" 
#include <stdlib.h> 

#define PORT_DEFAULT 53
#define TIMEOUT_DEFAULT 3

void config_init(config_type *config) {

    config->timeout = TIMEOUT_DEFAULT;
    config->port = PORT_DEFAULT;

    return;
}