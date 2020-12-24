all: dns_header.o defs.o
	gcc -w defs.o dns_header.o sniffer.c -lpcap -o sniffer
	if [ -e defs.h.gch ]; then rm defs.h.gch; fi
	if [ -e dns_header.h.gch ]; then rm dns_header.h.gch; fi
	if [ -e dns_header.o ]; then rm dns_header.o; fi
	if [ -e defs.o ]; then rm defs.o; fi

dns_header.o:
	gcc -c dns_header.c -o dns_header.o

 defs.o:
	gcc -c defs.c -o defs.o

clean:
	if [ -e sniffer ]; then rm sniffer; fi
