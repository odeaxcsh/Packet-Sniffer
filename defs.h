#ifndef __DEFS_
#define __DEFS_

#include <netinet/in.h>

#define BUFFERS_SIZE 1024

#define UNSUPPORTED 0
#define ETHERNET_ADDR_LEN 6
#define ETHERNET_LEN (2*ETHERNET_ADDR_LEN + 2)

// #define STATUS_TAG_ENABLED
// #define PACKET_TAG_ENABLED
#if defined(PROTOCOL_LOG_TAG_ENABLED)
#define PROTOCOL_TAG "(Protocol count) "
#else 
#define PROTOCOL_TAG ""
#endif
#if defined(STATUS_TAG_ENABLED)
#define STATUS_TAG "(status) "
#else
#define STATUS_TAG ""
#endif
#if defined(PACKET_TAG_ENABLED)
#define PACKET_TAG "(packet) "
#else
#define PACKET_TAG ""
#endif

extern const char *message_types_names[];

enum MESSAGES_TYPES
{
    HTTP = 1,
    DNS = 2
};

struct Ethernet_header
{
    u_char dest[ETHERNET_ADDR_LEN];
    u_char source[ETHERNET_ADDR_LEN];
    u_short type;
};

struct IP_header
{
    u_char version_header_len;
        #define IP_header_len(ip_header) ((((ip_header)->version_header_len) & 0x0f) << 2)
        #define IP_version(ip_header) ((((ip_header)->version_header_len) & 0xf0) >> 4)
    u_char DSCP;
    u_short total_len;
    u_short id;
    u_short flag_offest;
    u_char time_to_live;
    u_char protocol;
    u_short check_sum;
    struct in_addr dest;
    struct in_addr source;
};

extern const char *transport_header_types_names[];

enum transport_header_type
{
    UNKNOWN = 0,
    TCP = 1,
    UDP = 2
};

#define BOTH (TCP|UDP)


struct TCP_header
{
    u_short source_port;
    u_short dest_port;
    u_int sequent_number;
    u_int acknowledgment_number;
    u_char header_len;
    u_char flags;
        #define TCP_header_len(tcp_header) (((((struct TCP_header*)tcp_header)->header_len) & 0xf0) >> 2)
        #define TCP_flags(tcp_header) ((((struct TCP_header*)tcp_header)->flags) | ((((tcp_header)->header_len) & 0x0f) << 8))
    
    u_short window_size;
    u_short check_sum;
    u_short urgent;
};

struct UDP_header
{
    u_short source_port;
    u_short dest_port;
    u_short length;
    u_short checksum;
};

struct Formatted_packet
{
    const struct Ethernet_header *ethernet;
    const struct IP_header *IP;
    const void *transport_header;
    int transport_type;
    const u_char *message;
    u_int message_len;
};

struct Conversation
{
    u_short dest_port;
    u_short source_port;
    struct in_addr dest_ip;
    struct in_addr source_ip;
    int protocol;
    int packet_count;
    int total_packet_len;
    int totoal_packet_payload_len;
    int a_to_bo_count;
    int b_to_a_count;
};

struct Formatted_packet format(const u_char*, int);
#endif
