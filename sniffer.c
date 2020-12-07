#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#include "defs.h"

u_short reverse_bytes(u_short origin)
{
    u_short reversed = 0;
    for(int i = 0; i < sizeof(origin); ++i) {
        reversed =  reversed*256 + (origin%256);
        origin /= 256;
    }
    return reversed;
}

int message_type(struct TCP_IP_packet pakcet)
{
    return HTTP;
}

void HTTP_message_analyser(const char *message, int len)
{
    char *message_cpy = (char *)malloc((len + 1) * sizeof(char));
    strcpy(message_cpy, message);
    message_cpy[len] = '\0';

    char *type = strtok(message_cpy, "/ ");
    char status_line[BUFFERS_SIZE];
    if(!strcmp(type, "HTTP")) { //Message is a response
        char *version = strtok(NULL, " ");
        char *status_code = strtok(NULL, " ");
        char *phrase = strtok(NULL, "\r");
        sprintf(status_line, "%s/%s: %s[%s]", type, version, phrase, status_code);
    } else if(!strcmp(type, "GET") || !strcmp(type, "POST")) { //Message is a request
        char *request = type;
        char *argument = strtok(NULL, " ");
        type = strtok(NULL, "/");
        char *version = strtok(NULL, "\r");
        sprintf(status_line, "%s-%s: %s(%s)", type, version, request, argument);
    } else return;

    char *names_values[BUFFERS_SIZE];
    char header[BUFFERS_SIZE] = { 0 };
    int num = 0;
    do {
        names_values[num++] = strtok(NULL, "\n:"); 
        names_values[num++] = strtok(NULL, "\r");
    } while(strcmp("\r", names_values[num-2]));
    for(int i = 0; i < (num-2); i+=2)
        sprintf(header + strlen(header), "%s = %s\n", names_values[i], names_values[i+1]);
    syslog(LOG_INFO, "Status:%s \nheaders: %s\n", status_line, header);
    free(message_cpy);
}

void call_back_function(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct TCP_IP_packet formatted = format(packet, pkthdr->len);
    char source[INET_ADDRSTRLEN], dest[INET_ADDRSTRLEN], packet_info[BUFFERS_SIZE];
    inet_ntop(AF_INET, &(formatted.IP->dest), source, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(formatted.IP->source), dest, INET_ADDRSTRLEN);
    sprintf(packet_info, "Souce: %s:%d\n""Destn: %s:%d\n""Recieved at: %ld:%06ld\n""packet length: %d\n""Message length: %d\n",
    source, reverse_bytes(formatted.TCP->source_port), dest, reverse_bytes(formatted.TCP->dest_port), (const long int)(pkthdr->ts.tv_sec), (const long int)(pkthdr->ts.tv_usec), pkthdr->len ,formatted.message_len);

    syslog(LOG_INFO, "A packet captured: \n%s\n", packet_info);
    if(message_type(formatted) == HTTP) {
        HTTP_message_analyser(formatted.message, formatted.message_len);
    }
}

int main(int argc, char *argv[])
{
    char *device_name, pcap_error[PCAP_ERRBUF_SIZE] = { 0 };

    openlog("Sniffer", 0, LOG_USER);
    if(argc >= 2)
        device_name = argv[1];
    else {
        syslog(LOG_DEBUG, "Using default device...");
        if ( (device_name = pcap_lookupdev(pcap_error)) == NULL) {
            syslog(LOG_ERR, "Couldn't find default device: %s", pcap_error);
            return 1;
        } 
    }
    syslog(LOG_INFO, "Running on device: %s", device_name);

    bpf_u_int32 mask, net;
    if(pcap_lookupnet(device_name, &net, &mask, pcap_error) == -1) {
        syslog(LOG_ERR, "Couldn't get netmask for device %s: %s", device_name, pcap_error);
        return 1;
    }

    pcap_t *handle = pcap_open_live(device_name, BUFSIZ, 1, 1000, pcap_error);
    if(handle == NULL) {
        syslog(LOG_ERR, "Couldn't open device %s: %s", device_name, pcap_error);
        return 1;
    }

    struct bpf_program compiled;
    char filter_expression[] = "tcp port 80 && ((ip && (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)) || (ip6 && ((ip6[4:2] << 1) != 0)))";
    if(pcap_compile(handle, &compiled, filter_expression, 0, net) == -1) {
        syslog(LOG_ERR, "Couldn't compile filter expression '%s'", filter_expression);
        return 1;
    }

    if(pcap_setfilter(handle, &compiled) == -1) {
        syslog(LOG_ERR, "Couldn't set filter on device: %s", pcap_geterr(handle));
        return 1;
    }

    pcap_loop(handle, -1, call_back_function, NULL);
    pcap_close(handle);
}

