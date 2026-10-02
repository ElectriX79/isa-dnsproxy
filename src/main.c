#include <stdio.h>
#include <sysexits.h> 
#include "./include/config.h"
#define ERROR 1
#define SUCCESS 0

int main(int argc, char *argv[]) {
    // Declaration and inicialization of main program configuration structure 
    config_type config = {0};
    config_init(&config);

    if(arg_parser(argc, argv) == EX_USAGE) {
        return EX_USAGE;
    }
    
}