 #include <stdlib.h>
 #include <stdio.h>
 #include <stdbool.h>
 #include <strings.h>
 #include <string.h>
 #include <stdint.h>
 #include <sysexits.h> 
 #include <arpa/inet.h>
 #include "../include/config.h" 

 #define PORT_INVALID 0

 #define TIMEOUT_INVALID 0

 #define URL_INVALID 1
 #define URL_VALID 0


 int validate_url(const char *url) {
    const char *start = NULL;

    if(strncasecmp(url, "https://", strlen("https://")) == 0) {
        start = url+strlen("https://");
    }

    else if(strncasecmp(url, "http://", strlen("http://")) == 0) {
        start = url+strlen("http://");
    }

    if(!start) {
        return URL_INVALID; 
    }

    if(strcspn(start, "/?#:@") == 0 ) {
        return URL_INVALID;
    }

    return URL_VALID;
 }

uint16_t validate_port(char *port) {
        char *endpoint;
        long int number;

        number = strtol(port, &endpoint, 10);

        if(endpoint == port) {
            fprintf(stderr, "Port is not a number \n");
            return PORT_INVALID;
        }

        if(*endpoint != '\0') {
            fprintf(stderr, "Invalid character: %c\n", *endpoint); 
            return PORT_INVALID; 
        } 

        if(number < 1 || number > 65535) {
            fprintf(stderr, "Port number out of range\n");
            return PORT_INVALID;
        }

        return (uint16_t)number;
 }

 uint16_t validate_timeout(char *timeout) {
    char *endpoint;
    long int number;

    number = strtol(timeout, &endpoint, 10);

    if(timeout == endpoint) {
        fprintf(stderr, "Timeout is not a number\n");
        return TIMEOUT_INVALID;
    }
    if(*endpoint != '\0') {
        fprintf(stderr, "Invalid character: %c \n", *endpoint);
        return TIMEOUT_INVALID;
    }
    if(number < 1 || number > 3600) {
        return TIMEOUT_INVALID;
    }

    return (uint16_t)number;
 }

 
 int arg_parser(char *argv[], int argc, config_type *cfg) {

    bool seen_url = false; 
    bool seen_port = false;
    bool seen_addr = false;
    bool seen_timeout = false;
    for(int i = 1; i < argc; i++) {
        if((strcmp(argv[i], "--help") == 0) || strcmp(argv[i], "-h") == 0 ) {
            print_help();
            exit(EXIT_SUCCESS);
        }
    }

    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "-u") == 0) {
            if(seen_url) {
                fprintf(stderr, "Duplicit -u switch \n");
                return EX_USAGE;
            }
            if(i + 1 < argc) {
                if(validate_url(argv[i+1]) != 0) {
                fprintf(stderr, "Invalid URL format \n");
                return EX_USAGE; 
                }
                seen_url = true; 
                cfg->DOH_URL = argv[i+1];
                i++; 
            }
            else {
                fprintf(stderr, "Missing url \n");
                return EX_USAGE; 
            }
        }
        else if(strcmp(argv[i], "-p") == 0 ) {
            if(seen_port) {
                fprintf(stderr, "Duplicit -p switch \n");
                return EX_USAGE;
            }
            if(i+1 >= argc) {
                fprintf(stderr,"Missing port number \n");
                return EX_USAGE;
            }
            if((cfg->port = validate_port(argv[i+1])) == PORT_INVALID) {
                return EX_USAGE;
            }
            seen_port = true;
            i++;
        }

        else if(strcmp(argv[i], "-a") == 0) {
            if(seen_addr) {
                fprintf(stderr, "Duplicit address\n");
                return EX_USAGE;
            } 
            if(i+1 >= argc) {
                fprintf(stderr, "Missing address\n");
                return EX_USAGE;
            }
            if(inet_pton(AF_INET, argv[i+1], &(((struct sockaddr_in *)&cfg->ip_addr)->sin_addr).s_addr) == 1) {
                    ((struct sockaddr_in *)&cfg->ip_addr)->sin_family = AF_INET; 
                    cfg->default_address = false;
            }
            else if(inet_pton(AF_INET6, argv[i+1], &(((struct sockaddr_in6 *)&cfg->ip_addr)->sin6_addr).s6_addr) == 1) {
                    ((struct sockaddr_in6 *)&cfg->ip_addr)->sin6_family = AF_INET6; 
                    cfg->default_address = false;
            }

            if(cfg->default_address) {
                fprintf(stderr, "Invalid address\n");
                return EX_USAGE;
            }
            seen_addr = true;
            i++;
        }
        else if(strcmp(argv[i], "-z") == 0) {
            if(i+1 >= argc) {
                fprintf(stderr, "No zonefile provided\n");
                return EX_USAGE;
            }
            if(cfg->zone_file.count == 64) {
                fprintf(stderr, "Maximum zonefiles reached (64)");
                return EX_USAGE;
            }
            (cfg->zone_file).items[(cfg->zone_file).count] = argv[i+1];
            (cfg->zone_file).count++; 
            i++;
        }   

        else if(strcmp(argv[i], "-b") == 0) {
            if(i+1 >= argc) {
                fprintf(stderr, "No blocklist file provided\n");
                return EX_USAGE;
            }
            if(cfg->block_list.count == 64) {
                fprintf(stderr, "Maximum blocklist files reached (64)");
                return EX_USAGE;
            }
            (cfg->block_list).items[(cfg->block_list).count] = argv[i+1];
            (cfg->block_list).count++;
            i++;
        }
        else if(strcmp(argv[i], "--insecure") == 0) {
            cfg->insecure = true;
        }
        else if(strcmp(argv[i], "-w") == 0) {
            if(seen_timeout) {
                fprintf(stderr, "Duplicit timeout\n");
                return EX_USAGE;
            }
            if(i+1 >= argc) {
                fprintf(stderr, "Missing timeout\n");
                return EX_USAGE;
            }
            if((cfg->timeout = validate_timeout(argv[i+1])) == 0) {
                fprintf(stderr, "Invalid timeout format\n");
                return EX_USAGE;
            }
            seen_timeout = true; 
            i++;
        }
        else {
            fprintf(stderr, "Invalid command\n");
            return EX_USAGE;
        }
    }
    if(!seen_url) {
        fprintf(stderr, "Missing url address\n");
        return EX_USAGE;
    } 


    if(seen_addr) {
        if((cfg->ip_addr).ss_family == AF_INET) {
            (((struct sockaddr_in *)&cfg->ip_addr)->sin_port) = htons(cfg->port);
        }
        else if((cfg->ip_addr).ss_family == AF_INET6) {
            (((struct sockaddr_in6 *)&cfg->ip_addr)->sin6_port) = htons(cfg->port);
        }
    }

    return EXIT_SUCCESS;
 }