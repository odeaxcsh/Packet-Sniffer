#ifndef __DNS_HEADER_
#define __DNS_HEADER_

#include <netinet/in.h>

#define DNS_header_size (sizeof(struct DNS_header))

struct DNS_header
{
    u_short id;
    u_short flags;
    #define DNS_QUERY_RESPONE(dns_header) (((dns_header)->flags >> 7) & 0x1)
    #define DNS_OPCODE(dns_header) ((((dns_header)->flags) >> 3) & 0x0f)
    #define DNS_RESPONSE_CODE(dns_header) (((dns_header)->flags >> 8) & 0x07)
    u_short questions_num;
    u_short answers_num;
    u_short athority_num;
    u_short additional_num;
};

extern const char *dns_response_codes_map[];
extern const char *dns_operation_codes_map[];
void format_dns_names(const u_char*, char*);
const char *dns_type(u_short);

void DNS_message_analyser(const u_char*, int);

#endif