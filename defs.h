#ifndef __DEFS_
#define __DEFS_

#include <netinet/in.h>

#define BUFFERS_SIZE 1024

#define ETHERNET_ADDR_LEN 6
#define ETHERNET_LEN (2*ETHERNET_ADDR_LEN + 2)

enum MESSAGES_TYPES
{
    HTTP
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
    struct in_addr source, dest;
};

struct TCP_header
{
    u_short source_port;
    u_short dest_port;
    u_int sequent_number;
    u_int acknowledgment_number;
    u_char header_len;
    u_char flags;
        #define TCP_header_len(tcp_header) ((((tcp_header)->header_len) & 0xf0) >> 2)
        #define TCP_flags(tcp_header) (((tcp_header)->flags) | ((((tcp_header)->header_len) & 0x0f) << 8))
    
    u_short window_size;
    u_short check_sum;
    u_short urgent;
};

struct TCP_IP_packet
{
    const struct Ethernet_header *ethernet;
    const struct IP_header *IP;
    const struct TCP_header *TCP;
    const u_char *message;
    u_int message_len;
};

struct TCP_IP_packet format(const u_char *packet, int pakcet_len)
{
    struct TCP_IP_packet formatted_packet;
    formatted_packet.ethernet = (struct Ethernet_header*)(packet);
    formatted_packet.IP = (struct IP_header*)(packet + ETHERNET_LEN);
    u_char ip_size = IP_header_len(formatted_packet.IP);
    formatted_packet.TCP = (struct TCP_header*)(packet + ETHERNET_LEN + ip_size);
    u_char tcp_size = TCP_header_len(formatted_packet.TCP);
    formatted_packet.message = (packet + ETHERNET_LEN + ip_size + tcp_size);
    formatted_packet.message_len = pakcet_len - ETHERNET_LEN + ip_size + tcp_size;
    return formatted_packet;
}

#endif