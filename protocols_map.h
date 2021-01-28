#if !defined(DEF_PROTOCOLS_MAP)
#define DEF_PROTOCOLS_MAP

#include "defs.h"

struct Protocol
{
    int transport_protocol_type;
    int packet_count;
    int using_port;
    char *name;
};

struct Protocol protocols[]
=
{
    {UNKNOWN, 0, 0, "UNKNOWN"},
    {BOTH, 0, 1, "TCPMUX"},
    {BOTH, 0, 7,"Echo"},
    {BOTH, 0, 17, "QOTD"},
    {BOTH, 0, 19, "CHARGEN"},
    {TCP, 0, 20, "FTP_Data"},
    {TCP, 0, 21, "FTP_Command"},
    {TCP, 0, 22, "SSH"},
    {TCP, 0, 23, "TELNET"},
    {BOTH, 0, 25, "SMTP"},
    {BOTH, 0, 37, "Time"},
    {UDP, 0, 53, "DNS"},
    {BOTH, 0, 69, "TFTP"},
    {TCP, 0, 80, "HTTP"},
    {BOTH, 0, 110, "POP3"},
    {TCP, 0, 119, "NNTP"},
    {TCP, 0, 123, "NTP"},
    {BOTH, 0, 143, "IMAP4"},
    {TCP, 0, 443, "HTTPS"}
};

#define PROTOCOL_COUNT sizeof(protocols)/sizeof(struct Protocol)

#endif 
