#include <sys/types.h>
#include "defs.h"

#define BUFFERS_SIZE 1024

#define UNSUPPORTED 0
#define ETHERNET_ADDR_LEN 6
#define ETHERNET_LEN (2*ETHERNET_ADDR_LEN + 2)

const char *message_types_names[] = 
{
    "UNSUPPORTED",
    "HTTP",
    "DNS"
};

const char *transport_header_types_names[] = 
{
    "UNSUPPORTED",
    "TCP",
    "UDP"
};

struct Formatted_packet format(const u_char *packet, int pakcet_len)
{
    struct Formatted_packet formatted_packet;
    formatted_packet.ethernet = (struct Ethernet_header*)(packet);
    formatted_packet.IP = (struct IP_header*)(packet + ETHERNET_LEN);
    u_char ip_size = IP_header_len(formatted_packet.IP);
    formatted_packet.transport_header = (struct TCP_header*)(packet + ETHERNET_LEN + ip_size);
    u_char transport_size = 0;
    switch (formatted_packet.IP->protocol)
    {
    case 0x06: //TCP header
        formatted_packet.transport_type = TCP;
        transport_size = TCP_header_len(formatted_packet.transport_header);
        break;
    case 0x11: //UDP header
        formatted_packet.transport_type = UDP;
        transport_size = sizeof(struct UDP_header);
        break;
    default:
        formatted_packet.transport_type = UNSUPPORTED;
        transport_size = 0;
    }
    formatted_packet.message = (packet + ETHERNET_LEN + ip_size + transport_size);
    formatted_packet.message_len = pakcet_len - (ETHERNET_LEN + ip_size + transport_size);
    return formatted_packet;
}