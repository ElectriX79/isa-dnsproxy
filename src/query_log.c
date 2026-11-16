#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "query_log.h"

const char* dns_type_name(uint16_t type) {
    switch(type) {
        case 1: return "A";
        case 2: return "NS";
        case 3: return "MD";
        case 4: return "MF";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 7: return "MB";
        case 8: return "MG";
        case 9: return "MR";
        case 10: return "NULL";
        case 11: return "WKS";
        case 12: return "PTR";
        case 13: return "HINFO";
        case 14: return "MINFO";
        case 15: return "MX";
        case 16: return "TXT";
        case 17: return "RP";
        case 18: return "AFSDB";
        case 19: return "X25";
        case 20: return "ISDN";
        case 21: return "RT";
        case 22: return "NSAP";
        case 23: return "NSAP-PTR";
        case 24: return "SIG";
        case 25: return "KEY";
        case 26: return "PX";
        case 27: return "GPOS";
        case 28: return "AAAA";
        case 29: return "LOC";
        case 30: return "NXT";
        case 31: return "EID";
        case 32: return "NIMLOC";
        case 33: return "SRV";
        case 34: return "ATMA";
        case 35: return "NAPTR";
        case 36: return "KX";
        case 37: return "CERT";
        case 38: return "A6";
        case 39: return "DNAME";
        case 40: return "SINK";
        case 41: return "OPT";
        case 42: return "APL";
        case 43: return "DS";
        case 44: return "SSHFP";
        case 45: return "IPSECKEY";
        case 46: return "RRSIG";
        case 47: return "NSEC";
        case 48: return "DNSKEY";
        case 49: return "DHCID";
        case 50: return "NSEC3";
        case 51: return "NSEC3PARAM";
        case 52: return "TLSA";
        case 53: return "SMIMEA";
        case 55: return "HIP";
        case 56: return "NINFO";
        case 57: return "RKEY";
        case 58: return "TALINK";
        case 59: return "CDS";
        case 60: return "CDNSKEY";
        case 61: return "OPENPGPKEY";
        case 62: return "CSYNC";
        case 63: return "ZONEMD";
        case 64: return "SVCB";
        case 65: return "HTTPS";
        case 66: return "DSYNC";
        case 67: return "HHIT";
        case 68: return "BRID";
        case 99: return "SPF";
        case 100: return "UINFO";
        case 101: return "UID";
        case 102: return "GID";
        case 103: return "UNSPEC";
        case 104: return "NID";
        case 105: return "L32";
        case 106: return "L64";
        case 107: return "LP";
        case 108: return "EUI48";
        case 109: return "EUI64";
        case 128: return "NXNAME";
        case 249: return "TKEY";
        case 250: return "TSIG";
        case 251: return "IXFR";
        case 252: return "AXFR";
        case 253: return "MAILB";
        case 254: return "MAILA";
        case 255: return "ANY";
        case 256: return "URI";
        case 257: return "CAA";
        case 258: return "AVC";
        case 259: return "DOA";
        case 260: return "AMTRELAY";
        case 261: return "RESINFO";
        case 262: return "WALLET";
        case 263: return "CLA";
        case 264: return "IPN";
        case 32768: return "TA";
        case 32769: return "DLV";
        default: return NULL;
    }
}

static const char* rcode_name(int rcode) {
    switch(rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMP";
        case 5: return "REFUSED";
        case 6: return "YXDOMAIN";
        case 7: return "YXRRSET";
        case 8: return "NXRRSET";
        case 9: return "NOTAUTH";
        case 10: return "NOTZONE";
        case 11: return "DSOTYPENI";
        default: return NULL;
    }
}

void query_log(const struct sockaddr_storage *client, const uint8_t *msg, bool question_parsed,
               uint16_t qtype, const char *verdict, int rcode) {
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);

    char date[32];
    char zone[8];
    strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S", &tm);
    strftime(zone, sizeof(zone), "%z", &tm);

    char timestamp[48];
    snprintf(timestamp, sizeof(timestamp), "%s%.3s:%s", date, zone, zone + 3);

    char ip[INET6_ADDRSTRLEN];
    char client_str[INET6_ADDRSTRLEN + 16];

    if(client->ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)client;
        inet_ntop(AF_INET, &a->sin_addr, ip, sizeof(ip));
        snprintf(client_str, sizeof(client_str), "%s:%u", ip, ntohs(a->sin_port));
    } else {

        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)client;
        inet_ntop(AF_INET6, &a->sin6_addr, ip, sizeof(ip));
        snprintf(client_str, sizeof(client_str), "[%s]:%u", ip, ntohs(a->sin6_port));
    }

    char qname[1100];
    size_t len = 0;

    if(!question_parsed) {
        strcpy(qname, "-");
    } else if(msg[12] == 0) {
        strcpy(qname, ".");
    } else {
        size_t i = 12;
        while(msg[i] != 0) {
            uint8_t label_len = msg[i];
            i++;
            for(uint8_t j = 0; j < label_len; j++) {
                uint8_t c = msg[i];
                i++;
                if(c >= 'A' && c <= 'Z') {
                    c = c + ('a' - 'A');
                }
                if(c == '.' || c == ';' || c == '(' || c == ')' || c == '@' || c == '$' || c == '"' || c == '\\') {
                    qname[len++] = '\\';
                    qname[len++] = (char)c;
                } else if(c < 0x21 || c > 0x7E) {
                    len += snprintf(qname + len, sizeof(qname) - len, "\\%03u", c);
                } else {
                    qname[len++] = (char)c;
                }
            }
            qname[len++] = '.';
        }
        qname[len] = '\0';
    }

    char qtype_str[16];
    if(!question_parsed) {
        strcpy(qtype_str, "-");
    } else if(dns_type_name(qtype) != NULL) {
        strcpy(qtype_str, dns_type_name(qtype));
    } else {
        snprintf(qtype_str, sizeof(qtype_str), "TYPE%u", qtype);
    }

    char rcode_str[16];
    if(rcode == RCODE_NONE) {
        strcpy(rcode_str, "-");
    } else if(rcode_name(rcode) != NULL) {
        strcpy(rcode_str, rcode_name(rcode));
    } else {
        snprintf(rcode_str, sizeof(rcode_str), "RCODE%d", rcode);
    }

    char line[1300];
    int n = snprintf(line, sizeof(line), "%s %s %s %s %s %s\n",
                     timestamp, client_str, qname, qtype_str, verdict, rcode_str);
    if(write(STDOUT_FILENO, line, n) < 0) {
        perror("write");
    }
}