#include <stdio.h>
#include <sysexits.h> 
#include "config.h"
#include "arg_parser.h"
#include "blocklist_parser.h"
#define ERROR 1
#define SUCCESS 0

int main(int argc, char *argv[]) {
    // Declaration and inicialization of main program configuration structure 
    config_type config = {0};
    config_init(&config);

    if(arg_parser(argv, argc, &config) == EX_USAGE) {
        return EX_USAGE;
    }

    if(blocklist_parser(&config) == EX_USAGE) {
        return EX_CONFIG; 
    }

    hashtable_destructor(config.h_table);


    return 0;
    
}