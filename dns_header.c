#include "dns_header.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>

const char *dns_type(u_short code)
{
    switch (code)
    {
    case 0x0001:
        return "A";
    case 0x0002:
        return "NS";
    case 0x0005:
        return "CNAME";
    case 0x0006:
        return "SOA";
    case 0x000f:
        return "MX";
    case 0x001c:
        return "AAAA";
    default:
        return "UNKNOWN";
    }
}

const char *dns_response_codes_map[] =
{
    "No Error",
    "Format Error",
    "Server Failure",
    "Name Error",
    "Not Implemented",
    "Refused",
    "YX Domain",
    "YX RR Set",
    "NX RR set",
    "Not Athority",
    "Not Zone"
};

const char *dns_operation_codes_map[] =
{
    "QUERY",
    "IQUERY",
    "STATUS",
    "REVERSED",
    "NOTIFY",
    "UPDATE"
};

void DNS_message_analyser(const u_char *message, int len) 
{
    struct DNS_header *header = (struct DNS_header*)message;
    message = message + sizeof(struct DNS_header);
    syslog(LOG_INFO, "FLAGS: %d", header->flags);
    syslog(LOG_INFO, "[Identifier: %x]", ntohs(header->id));
    syslog(LOG_INFO, "[Response/Query: %s[%u]]", DNS_QUERY_RESPONE(header) ? "Response" : "Query", DNS_QUERY_RESPONE(header));
    if(DNS_QUERY_RESPONE(header))
        syslog(LOG_INFO, "[Response code: %s[%u]]", dns_response_codes_map[DNS_RESPONSE_CODE(header)], DNS_RESPONSE_CODE(header));
    else
      syslog(LOG_INFO, "[Operation: %s[%u]]", dns_operation_codes_map[DNS_OPCODE(header)], DNS_OPCODE(header));

    syslog(LOG_INFO, "Question count: %u", ntohs(header->questions_num));
    syslog(LOG_INFO, "Answer record count: %u", ntohs(header->answers_num));
    syslog(LOG_INFO, "Athority record count: %u", ntohs(header->athority_num));
    syslog(LOG_INFO, "Addtional record count: %u", ntohs(header->additional_num));

    for(int i = 1; i <= ntohs(header->questions_num); ++i) {
        syslog(LOG_INFO, "(%d).Question.name: %s", i, message);
        message = message + strlen(message) + 1;
        syslog(LOG_INFO, "(%d).Question.type: %s", i, dns_type(htons(*((u_short*)message))));
        message += 4;
    }

    int answers_total_count = ntohs(header->answers_num) + ntohs(header->athority_num);// + ntohs(header->additional_num);
    for(int i = 1; i <= answers_total_count; ++i) {
        //Skip label :? 
        if((*message) == 0xc0)
            message += 2;
        else ++message;
        int answer_type = htons(*((u_short*)message));
        message += 4;
        int ttl = htonl(*((u_int*)message));
        message += 4;
        int length = ntohs(*((u_short*)message));
        message += 2;

        syslog(LOG_INFO, "(%d).Answer.type: %s", i, dns_type(answer_type));
        syslog(LOG_INFO, "(%d).Answer.time-to-live: %04us", i, ttl);
        syslog(LOG_INFO, "(%d).Answer.message.len: %d", i, length);

        switch(answer_type) {
            case 0x000f: 
                syslog(LOG_INFO, "(%d).MX.Prefrence: %d", i, ntohs(*((u_short*)message)));
                length -= 2;
                message += 2;
            case 0x0002: case 0x0005:
                length -= 2;
                syslog(LOG_INFO, "(%d).Answer.message: %.*s", i, length, message);
                message += strlen(message);
                break;
            case 0x0001:
                syslog(LOG_INFO, "(%d).Answer.message: %s", i, inet_ntoa(*((struct in_addr*) message)));
                message += 4;
                break;
            case 0x001c:
                syslog(LOG_INFO, "(%d).Answer.message: %s", i, "IPv6 is not supported yet!");
        }
    }
}