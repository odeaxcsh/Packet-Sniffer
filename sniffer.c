#include <pcap.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>

#define INPUTS_TIMEOUT 3 //seconds
#define LOGS_DIST 30

#include "linked_list.h"
#include "dns_header.h"
#include "defs.h"

int message_reporter_is_working = 0;

#define swap(x,y) do \ 
   { unsigned char swap_temp[sizeof(x) == sizeof(y) ? (signed)sizeof(x) : -1]; \
     	memcpy(swap_temp,&y,sizeof(x)); \
     	memcpy(&y,&x,       sizeof(x)); \
     	memcpy(&x,swap_temp,sizeof(x)); \
    } while(0)

struct Status_information
{
	int tcp_count, udp_count;
	struct Linked_list *list;
};

int isnumber(const char *string) {
   char *end = NULL;
   strtol(string, &end, 0);
   return end && !(*end);
}

int message_type(struct Formatted_packet packet)
{
	u_short source_port, dest_port;
	if(packet.transport_type == TCP) {
		struct TCP_header *tcp = (struct TCP_header*)packet.transport_header;
		source_port = ntohs(tcp->source_port), dest_port = ntohs(tcp->dest_port);
	} else if(packet.transport_type == UDP) {
		struct UDP_header *udp = (struct UDP_header*)packet.transport_header;
		source_port = ntohs(udp->source_port), dest_port = ntohs(udp->dest_port); 
	}

	if(packet.transport_type == TCP && (packet.message_len) && (source_port == 80 || dest_port == 80))
		return HTTP;
	else if(packet.transport_type == UDP && (packet.message_len) && (source_port == 53 || dest_port == 53))
		return DNS;
	else return UNSUPPORTED;
}

void message_reporter_update(struct Formatted_packet packet, int len, struct Status_information *info)
{
	while(message_reporter_is_working)
	;

	struct Linked_list *list = info->list;
	u_short source_port, dest_port;
	if(packet.transport_type == TCP) {
		struct TCP_header *tcp = (struct TCP_header*)packet.transport_header;
		source_port = tcp->source_port, dest_port = tcp->dest_port;
	} else if(packet.transport_type == UDP) {
		struct UDP_header *udp = (struct UDP_header*)packet.transport_header;
		source_port = udp->source_port, dest_port = udp->dest_port; 
	}
	struct in_addr source_ip = packet.IP->source, dest_ip = packet.IP->dest;
	int is_a_to_b = (source_ip.s_addr) < (dest_ip.s_addr);

	if ((source_ip.s_addr) == (dest_ip.s_addr))
		is_a_to_b = source_port < dest_port;
			
	if(!is_a_to_b) {
		swap(source_ip, dest_ip);
		swap(dest_port, source_port);
	}

	struct Linked_list_node *current = list->head->next;
	while(current != list->tail) {
		struct Conversation *object = (struct Conversation*)current->object;
		if(object->source_port == source_port && object->dest_port == dest_port &&
			object->source_ip.s_addr == source_ip.s_addr && object->dest_ip.s_addr == dest_ip.s_addr &&
			packet.transport_type == object->protocol) {
			++object->packet_count;
			object->total_packet_len += len;
			object->totoal_packet_payload_len += packet.message_len;
			if(is_a_to_b) 
				++object->a_to_bo_count;
			else ++object->b_to_a_count;
			break;
		} else current = current->next;
	}
	
	if(current == list->tail) {
		struct Conversation *conv = (struct Conversation *)malloc(sizeof(struct Conversation));
		conv->dest_ip = dest_ip;
		conv->source_ip = source_ip;
		conv->dest_port = dest_port;
		conv->source_port = source_port;
		conv->packet_count = 1;
		conv->total_packet_len = len;
		conv->totoal_packet_payload_len = packet.message_len;
		conv->protocol = packet.transport_type;
		conv->a_to_bo_count = is_a_to_b;
		conv->b_to_a_count = !is_a_to_b;
		Linked_list_push_front(list, conv);
		if(conv->protocol == TCP)
			++info->tcp_count;
		else if(conv->protocol == UDP)
			++info->udp_count;
	}
}

void *message_reporter(void *args)
{
	struct Status_information *info = (struct Status_information*)args;
	struct Linked_list *conv_list = info->list;
	char source[INET_ADDRSTRLEN], dest[INET_ADDRSTRLEN];
	int total_count = 0;
	#ifdef DEBUG_ON
	int prev_udp_count = 0, prev_tcp_count=0;
	#endif
	while(1) {
		message_reporter_is_working = 0;
		sleep(LOGS_DIST);
		message_reporter_is_working = 1;

		++total_count;
		int udp_count = 0, tcp_count = 0, count = 0;
		syslog(LOG_INFO, STATUS_TAG"GENERAL STATUS(%d):", total_count);
		struct Linked_list_node *current = conv_list->head->next;
		while(current != conv_list->tail) {
			++count;
			struct Conversation *object = (struct Conversation *)current->object;
			inet_ntop(AF_INET, &(object->dest_ip), source, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(object->source_ip), dest, INET_ADDRSTRLEN);
			if(object->protocol == TCP)
				++tcp_count;
			else if(object->protocol == UDP)
				++udp_count;
			syslog(LOG_INFO, STATUS_TAG"Conversation(%d).(%d) at [%s]", total_count, count,  transport_header_types_names[object->protocol]);
			syslog(LOG_INFO, STATUS_TAG"Source: %s:%d", source, ntohs(object->source_port));
			syslog(LOG_INFO, STATUS_TAG"Desten: %s:%d", dest, ntohs(object->dest_port));
			syslog(LOG_INFO, STATUS_TAG"packet count: <-%02d <-%02d->  %02d->, ", object->b_to_a_count, object->packet_count, object->a_to_bo_count);
			syslog(LOG_INFO, STATUS_TAG"Total size: %dB", object->total_packet_len);
			syslog(LOG_INFO, STATUS_TAG"Total net size: %dB", object->totoal_packet_payload_len);
			current = current->next;
		}
		#ifdef DEBUG_ON
		if(((tcp_count - prev_tcp_count) != info->tcp_count) || ((udp_count - prev_udp_count) != info->udp_count))
			syslog(LOG_ALERT, "[ERR]: A bug detected: Counting Conversation Problem.");
		prev_tcp_count = tcp_count;
		prev_udp_count = udp_count;
		#endif
		syslog(LOG_INFO, STATUS_TAG"(%d)-UDP Count: %d", total_count, udp_count);
		syslog(LOG_INFO, STATUS_TAG"(%d)-TCP Count: %d", total_count, tcp_count);
		syslog(LOG_INFO, STATUS_TAG"(%d)-New UDP: %d", total_count, info->udp_count);
		syslog(LOG_INFO, STATUS_TAG"(%d)-New TCP: %d", total_count, info->tcp_count);
		info->tcp_count = info->udp_count = 0;
	}
}

void message_reporter_init(struct Status_information *info)
{
	pthread_t thread_id;
	if(pthread_create(&thread_id, NULL, message_reporter, info))
		printf("General Reporter cannot be initialized!");
}

void HTTP_message_analyser(const char *message, int len)
{
	char *message_cpy = (char *)malloc((len + 1) * sizeof(char));
	strncpy(message_cpy, message, len);
	message_cpy[len] = '\0';

	char *type = strtok(message_cpy, "/ ");
	if(!strcmp(type, "HTTP")) { //Message is a response
		char *version = strtok(NULL, " ");
		char *status_code = strtok(NULL, " ");
		char *phrase = strtok(NULL, "\r");
		syslog(LOG_DEBUG, PACKET_TAG"[Status line: %s/%s: %s[%s]]", type, version, phrase, status_code);
	} else if(!strcmp(type, "GET") || !strcmp(type, "POST")) { //Message is a request
		char *request = type;
		char *argument = strtok(NULL, " ");
		type = strtok(NULL, "/");
		char *version = strtok(NULL, "\r");
		syslog(LOG_DEBUG, PACKET_TAG"[Status line: %s-%s: %s(%s)]", type, version, request, argument);
	} else {
		message_cpy[strlen(type)] = ' ';
		char *head = message_cpy, *current = message_cpy;
		while((head - message_cpy) < len-1) {
			if(*current == '\n' || *current == '\0') {
				*current = '\0';
				syslog(LOG_DEBUG, PACKET_TAG"HTTP Content: %s", head);
				head = current + 1;
			} else if(!isprint(*current))
				*current = '.';
			++current;
		} return;
	}

	char *names_values[BUFFERS_SIZE];
	int num = 0;
	do {
		names_values[num++] = strtok(NULL, "\n:"); 
		names_values[num++] = strtok(NULL, "\r");
	} while(strcmp("\r", names_values[num-2]));
	for(int i = 0; i < (num-2); i+=2)
		syslog(LOG_DEBUG, PACKET_TAG"[Header: %s = %s]", names_values[i], names_values[i+1]);
	free(message_cpy);
}

void call_back_function(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	static int count = 0;
	struct Formatted_packet formatted = format(packet, pkthdr->len);
	#if defined(DEBUG_ON)
	if((ntohs(formatted.IP->total_len) + sizeof(struct Ethernet_header)) != pkthdr->len)
		syslog(LOG_ERR, "[ERR]: A bug detected: Packet size doesn't match with headers information.");
	#endif
	message_reporter_update(formatted, pkthdr->len, (struct Status_information*) arg);
	int msg_type = message_type(formatted);
	if(msg_type == UNSUPPORTED)
		return;
	char source[INET_ADDRSTRLEN], dest[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(formatted.IP->dest), source, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(formatted.IP->source), dest, INET_ADDRSTRLEN);
	u_short source_port, dest_port;
	if(formatted.transport_type == TCP) {
		struct TCP_header *tcp = (struct TCP_header*)formatted.transport_header;
		source_port = tcp->source_port, dest_port = tcp->dest_port;
	} else if(formatted.transport_type == UDP) {
		struct UDP_header *udp = (struct UDP_header*)formatted.transport_header;
		source_port = udp->source_port, dest_port = udp->dest_port; 
	}
	syslog(LOG_DEBUG, PACKET_TAG"(%03u):packet captured: [%s][%s][%s]", ++(count), "IP", transport_header_types_names[formatted.transport_type], message_types_names[msg_type]);
	syslog(LOG_DEBUG, PACKET_TAG"Source: %s:%d", source, ntohs(source_port));
	syslog(LOG_DEBUG, PACKET_TAG"Desten: %s:%d", dest, ntohs(dest_port));
	syslog(LOG_DEBUG, PACKET_TAG"packet length: %d", pkthdr->len);
	syslog(LOG_DEBUG, PACKET_TAG"Message length: %d", formatted.message_len);

	switch (msg_type)
	{
	case HTTP:
		HTTP_message_analyser(formatted.message, formatted.message_len);
		break;

	case DNS:
		DNS_message_analyser(formatted.message, formatted.message_len);
	default:
		break;
	}
}

int main(int argc, char *argv[])
{
	char *device_name = NULL, pcap_error[PCAP_ERRBUF_SIZE] = { 0 };
	openlog("Sniffer", 0, LOG_USER);
	if(argc >= 2)
		device_name = argv[1];
	else {
		pcap_if_t *alldevs, *iterator;

		if(pcap_findalldevs(&alldevs, pcap_error) == -1) {
			printf("Couldn't find devices due to: %s\n", pcap_error);
			return 1;
		}

		int dev_count;
		for(dev_count = 0, iterator = alldevs; iterator; iterator = iterator->next, ++dev_count)
			printf("[%01d]-%-15s\t %s\n", dev_count+1, iterator->name, iterator->description);
		
		fd_set rfds;
		struct timeval tv;
		tv.tv_usec = 0;
		while(device_name == NULL) {
			FD_ZERO(&rfds);
			FD_SET(0, &rfds);
			tv.tv_sec = INPUTS_TIMEOUT;

			printf("Which device do you want to sniff? Enter device name or device number:(Time limitation: %ds): ", INPUTS_TIMEOUT);
			fflush(stdout);

			if(select(1, &rfds, NULL, NULL, &tv)) {
				char input[1024] = { 0 };
				scanf("%s", input);
				if(isnumber(input)) {
					int dev_num = 0;
					sscanf(input, "%d", &dev_num);
					if(dev_num <= dev_count) {
						iterator = alldevs;
						for(int i = 1; i < dev_num; ++i, iterator = iterator->next);
						device_name = iterator->name;
					} else printf("Invalid Number\n");
				} else {
					for(iterator = alldevs; iterator; iterator = iterator->next)
						if(!strcmp(iterator->name, input)) 
							break;
					
					if(iterator == NULL)
						printf("No such a device\n");
					else device_name = iterator->name;
				}
			} else {
				printf("Timed out \n"
				"Using default device...\n");
				device_name = alldevs->name;
			}
		}
		device_name = strdup(device_name);
		pcap_freealldevs(alldevs);
	}

	printf("Running on device: %s\n", device_name);

	bpf_u_int32 mask, net;
	if(pcap_lookupnet(device_name, &net, &mask, pcap_error) == -1) {
		printf("Couldn't get netmask for device %s: %s\n", device_name, pcap_error);
		return 1;
	}

	pcap_t *handle = pcap_open_live(device_name, BUFSIZ, 1, 1000, pcap_error);
	if(handle == NULL) {
		printf("Couldn't open device %s: %s\n", device_name, pcap_error);
		return 1;
	}

	struct bpf_program compiled;
	char filter_expression[] = "tcp || udp";
	if(pcap_compile(handle, &compiled, filter_expression, 0, net) == -1) {
		printf("Couldn't compile filter expression '%s'\n", filter_expression);
		return 1;
	}

	if(pcap_setfilter(handle, &compiled) == -1) {
		printf("Couldn't set filter on device: %s\n", pcap_geterr(handle));
		return 1;
	}

	struct Status_information *info = (struct Status_information*)malloc(sizeof(struct Status_information));
	info->list = create_linke_list();
	info->tcp_count = info->udp_count = 0;
	message_reporter_init(info);
	pcap_loop(handle, -1, call_back_function, (void*)info);
	pcap_close(handle);
	free(device_name);
}