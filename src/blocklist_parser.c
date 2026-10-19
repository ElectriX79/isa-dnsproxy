#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <ctype.h>
#include <sysexits.h>
#include <stdint.h> 
#include <errno.h> 
#include <stdlib.h>

#include "config.h"
#include "hash_table.h"


#define IGNORE_TOKEN -1 
#define INVALID_TOKEN -2
#define VALID_TOKEN 0

#define host_name_size (sizeof(HOSTS_HEADER_NAMES)) / (sizeof(HOSTS_HEADER_NAMES[0]))

int validate_token(char *token, bool first_token, char *file, int current_line) {
    if(strchr(token, ':') != NULL && first_token == true) {
        return IGNORE_TOKEN;
    } 
    uint16_t labels_cnt = 1;
    uint16_t charactersPerLable = 0;
    bool containsValidChar = false;
    uint16_t total_characters = 0;
    char *temp_token = token;
    char *to_lower = token;
    
    while(*temp_token != '\0') {
        if(!containsValidChar && *temp_token != '.' && !isdigit((unsigned char)*temp_token)) {
            containsValidChar = true;
        }
        if(*temp_token == '.') {
            if(charactersPerLable == 0) {
                fprintf(stderr,"%s:%i: Empty label\n",file, current_line);
                return INVALID_TOKEN;
            }
            labels_cnt++;
            charactersPerLable = 0;
            temp_token++;
            continue;
        }
        charactersPerLable++;
        if(charactersPerLable > 63) {
            fprintf(stderr, "%s:%i: Token´s label exceeded maximum length (63)\n", file, current_line);
            return INVALID_TOKEN;
        }
        if(labels_cnt > 127) {
            fprintf(stderr, "%s:%i: Domain contains too many labels (limit 127)\n", file, current_line);
            return INVALID_TOKEN;
        }
        if(!isalpha((unsigned char)*temp_token) && !isdigit((unsigned char)*temp_token) && *temp_token != '-' && *temp_token != '_') {
            fprintf(stderr, "%s:%i: Invalid character in domain: %c\n",file,current_line, *temp_token);
            return INVALID_TOKEN;
        }
        temp_token++;
    }
    if(*(strlen(token) + token - 1) == '.') {
        total_characters = strlen(token) - 1;
        *(strlen(token)+token-1) = '\0';
     }
    else {
        total_characters = strlen(token);
     }
    if(total_characters > 253) {
        fprintf(stderr, "%s:%i: Maximum domain length exceeded limit (253)\n",file, current_line);
        return INVALID_TOKEN; 
        }
    if(!containsValidChar) {
        return IGNORE_TOKEN;
     }
  
     static const char HOSTS_HEADER_NAMES[][22] = {
        "localhost",
        "localhost.localdomain",
        "local",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
        "ip6-localnet",
        "ip6-mcastprefix",
        "ip6-allnodes",
        "ip6-allrouters",
        "ip6-allhosts",
};

    while(*to_lower != '\0') {
        *to_lower = tolower((unsigned char) *to_lower);
        to_lower++; 
    }
    for(size_t hosts = 0; hosts < host_name_size; hosts++) {
        if(strcmp(token, HOSTS_HEADER_NAMES[hosts]) == 0) {
            return IGNORE_TOKEN;
        }
    }
    return VALID_TOKEN;
}


int process_line(hash_table *h_table, char *line, ssize_t len, char *file, int current_line) {
    char *temp_line = line;
    while(isspace((unsigned char)(*temp_line))) {
        temp_line++;
    }
    char *end_ptr;
    char *hashtag_ptr = strchr(line, '#');
    if(hashtag_ptr != NULL) {
        end_ptr = hashtag_ptr;
        *end_ptr = '\0';
        if(end_ptr != line) {
            end_ptr--;
        }
    }
    else {
        end_ptr = line + len -1; 
    }
    while(isspace((unsigned char)(*end_ptr))) {
        *end_ptr = '\0';
        if(end_ptr != line) {
            end_ptr--;
        }
    }

    bool first_token = true;
    while(1) {
        while(isspace((unsigned char)*temp_line)) {
            temp_line++;
        }
        if(*temp_line == '\0') {
            break;
        }
        uint16_t len_token = 0;
        char buff[256];
    
        while(!isspace(*temp_line) && *temp_line != '\0') {
            if(len_token > 255) {
            fprintf(stderr, "%s:%i: Domain exceeded length limit\n", file, current_line);
            return EX_CONFIG;
        }
            buff[len_token] = *temp_line;
            temp_line++;
            len_token++;
        }
        
        buff[len_token] = '\0'; 
        int return_res = validate_token(&buff[0], first_token, file, current_line);
        first_token = false;
        if(return_res == IGNORE_TOKEN) {
            continue;
        }
        else if(return_res == INVALID_TOKEN) {
            return EX_CONFIG;
        }
        else if(return_res == VALID_TOKEN) {
            htable_insert_element(h_table, &buff[0],NULL);
        }
    }
    return EXIT_SUCCESS;



}


uint32_t count_records(FILE *subor) { 
    int endfile;
    uint32_t records_count = 0;
    while((endfile = fscanf(subor, "%*s")) != EOF) {
        records_count++;
    }
    return records_count;
}


int blocklist_parser(config_type *cfg) {
    uint32_t records_count = 0;
    FILE *subor;
    for(uint16_t file_count = 0; file_count < cfg->block_list.count; file_count++) {
        subor = fopen(cfg->block_list.items[file_count], "r");
        if(subor == NULL) {
            fprintf(stderr, "%s:0: %s\n",cfg->block_list.items[file_count], strerror(errno));
            return EX_CONFIG; 
        }
        struct stat st;
        if(fstat(fileno(subor), &st) != 0) {
            fprintf(stderr, "%s:0: %s\n", cfg->block_list.items[file_count],strerror(errno));
            return EX_CONFIG;
        }
        if(!S_ISREG(st.st_mode)) {
            fprintf(stderr,"%s:0: Not a regular file\n", cfg->block_list.items[file_count]);
            return EX_CONFIG;
        }
        records_count += count_records(subor);

        fclose(subor);
    }
    hash_table *h_table;

    if(records_count == 0) {
        return EXIT_SUCCESS; 
    }

    h_table = hashtable_constructor(records_count);

    cfg->h_table = h_table; 

    for(uint16_t file_cnt = 0; file_cnt < cfg->block_list.count; file_cnt++) {
        subor = fopen(cfg->block_list.items[file_cnt], "r");
        if(subor == NULL) {
            fprintf(stderr, "%s:0: %s\n",cfg->block_list.items[file_cnt], strerror(errno));
            return EX_CONFIG;
        }
        char *line = NULL;
        size_t n = 0;
        ssize_t len; 
        unsigned long line_no = 0; 

        while((len = getline(&line, &n, subor)) != -1) {
            line_no++;
            int return_resp = process_line(h_table, line, len, cfg->block_list.items[file_cnt], line_no);
            if(return_resp == EX_CONFIG) {
                return EX_CONFIG;
            }
            free(line);
        }
        fclose(subor);
    }
    return EXIT_SUCCESS;
}