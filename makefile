all:
	gcc -w sniffer.c -lpcap -o sniffer
	if [ -e defs.h.gch]; then rm defs.h.gch; fi
clean:
	if [ -e sniffer ]; then rm sniffer; fi
