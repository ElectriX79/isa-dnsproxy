

struct pending {
    CURL *easy;
    int fd; 
    struct sockaddr_storage client;
    socklen_t client_len;
    uint16_t client_id;
    dns_query q;
    
}