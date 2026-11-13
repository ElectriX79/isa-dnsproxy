#include <stdio.h>
#include <sysexits.h> 
#include "config.h"
#include "arg_parser.h"
#include "blocklist_parser.h"
#include "zonefile_parser.h"
#include "event_loop.h"
#include "socket_binding.h"
#define ERROR 1
#define SUCCESS 0

int main(int argc, char *argv[]) {
    // Declaration and inicialization of main program configuration structure 
    config_type config = {0};
    config_init(&config);

    if(arg_parser(argv, argc, &config) == EX_USAGE) {
        return EX_USAGE;
    }

    if(blocklist_parser(&config) != 0) {
        return EX_CONFIG; 
    }
    zones *zn = NULL;
    if(zonefile_parser(&config, &zn) == EX_CONFIG) {
        return EX_CONFIG;
    }

    listeners list;
    int rc = open_sockets(&list, &config);
    if(rc != 0) {
        return rc;
    }
    rc = event_loop(&list);
    close_sockets(&list);
    return rc;
    
}