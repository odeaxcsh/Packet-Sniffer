#if !defined(JSON_FORMATTING)
#define JSON_FORMATTING

#include "defs.h"
#include <stdio.h>
#include <string.h>

#define MAX_BUFFER_LEN 1024

char *JSON_OUTPUT_FORMAT =
"{ \n"
"    \"genral\": { \n"
"        \"source\": { \n"
"            \"IP\": \"%s\", \n"
"            \"port\": %u \n"
"        }, \n"
"        \"destintaion\": { \n"
"            \"IP\": \"%s\", \n"
"            \"port\": %u \n"
"       }, \n"
"       \"protocol\": \"%s\" \n"
"   }\n"
"}, \n";

char *conver_to_json(struct Formatted_packet *packet)
{
    char buffer[MAX_BUFFER_LEN];
    
	u_short source_port, dest_port;
	if(packet->transport_type == TCP) {
		struct TCP_header *tcp = (struct TCP_header*)packet->transport_header;
		source_port = tcp->source_port, dest_port = tcp->dest_port;
	} else if(packet->transport_type == UDP) {
		struct UDP_header *udp = (struct UDP_header*)packet->transport_header;
		source_port = udp->source_port, dest_port = udp->dest_port; 
	}

	struct in_addr source_ip = packet->IP->source, dest_ip = packet->IP->dest;
	char source[INET_ADDRSTRLEN], dest[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(source_ip), source, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(dest_ip), dest, INET_ADDRSTRLEN);

    sprintf(buffer, JSON_OUTPUT_FORMAT, source, source_port, dest, dest_port, transport_header_types_names[packet->transport_type]);
    return strdup(buffer);
}

#endif