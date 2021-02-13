# Sniffer
Sniffer is a simple packet sniffer that analyzes HTTP and DNS packets with details and also gives general information about TCP and UDP conversations. Sniffer is written in c and uses libpcap library to read and maybe filter packets coming from network interface controllers.

## Compile and Run
To compile C files you must have libpcap installed, if you don't, this command do it for you.
``` bash
sudo apt install libpcap-dev # Debian and Ubuntu only
```

After installing libpcap, you can simply(if GCC is installed) use Make using `make`, `make normal`, `make separated`  to compile (difference of them is explained later) and `make clean` to delete the compiled file(It just removes Sniffer object file from directory).



Now after compiling code, the code can run via running this command
``` bash
sudo ./sniffer [the device you want to sniff]
```
If you don't know which device you want to sniff use `sudo ./sniffer` and then choose from the listed devices. If you still don't know your choice just let time pass, code will choose the first one automatically.


Program won't show you outputs directly rather generates some logs using syslog which in `ubuntu 20.04` they are stored in `/var/log/syslog/` but it differs from OS to OS.
you can also use the flowing command to get logs that is cleaner than searching through thousands of logs to find program logs.
``` bash
tail -f /var/log/syslog | grep Sniffer
```

## make
The code has an extra option which separates diffrent logs with some tags. this tags makes you able to watch particular logs which you want. for example you can use this command to see packets logs.
``` bash
tail -f /var/log/syslog | grep 'Sniffer: (packet)'
```
To enable this option use `make separated`.
Tags are `(packet)` for recieved packets log, `(status)` for conversations, and `(Protocol count)`.

The `make` and `make normal` disable this feature and both are the same.

## Supported OSs
First of all, Note that this code hasn't been tested in any operating system but `ubuntu 20.04`. If you are a Linux user there mustn't be problem in using Sniffer while you're having libpcap installed and also know how to find logs in your computer.

## Output Format
### Output when a HTTP packet is detected
``` html
Jan 13 22:07:13 sophie Sniffer: (001):packet captured: [IP][TCP][HTTP]
Jan 13 22:07:13 sophie Sniffer: Source: 216.239.38.120:80
Jan 13 22:07:13 sophie Sniffer: Desten: 192.168.43.103:33802
Jan 13 22:07:13 sophie Sniffer: packet length: 594
Jan 13 22:07:13 sophie Sniffer: Message length: 528
Jan 13 22:07:13 sophie Sniffer: [Status line: HTTP/1.1: Moved Permanently[301]]
Jan 13 22:07:13 sophie Sniffer: [Header: Location =  http://www.google.com/]
Jan 13 22:07:13 sophie Sniffer: [Header: Content-Type =  text/html; charset=UTF-8]
Jan 13 22:07:13 sophie Sniffer: [Header: Date =  Wed, 13 Jan 2021 18:37:04 GMT]
Jan 13 22:07:13 sophie Sniffer: [Header: Expires =  Fri, 12 Feb 2021 18:37:04 GMT]
Jan 13 22:07:13 sophie Sniffer: [Header: Cache-Control =  public, max-age=2592000]
Jan 13 22:07:13 sophie Sniffer: [Header: Server =  gws]
Jan 13 22:07:13 sophie Sniffer: [Header: Content-Length =  219]
Jan 13 22:07:13 sophie Sniffer: [Header: X-XSS-Protection =  0]
Jan 13 22:07:13 sophie Sniffer: [Header: X-Frame-Options =  SAMEORIGIN]
```

### Output when a DNS packet is detected
``` html
Jan 13 22:05:36 sophie Sniffer: (001):packet captured: [IP][UDP][DNS]
Jan 13 22:05:36 sophie Sniffer: Source: 192.168.43.103:49571
Jan 13 22:05:36 sophie Sniffer: Desten: 192.168.43.1:53
Jan 13 22:05:36 sophie Sniffer: packet length: 70
Jan 13 22:05:36 sophie Sniffer: Message length: 28
Jan 13 22:05:36 sophie Sniffer: [Identifier: a576]
Jan 13 22:05:36 sophie Sniffer: [Response/Query: Query[0]]
Jan 13 22:05:36 sophie Sniffer: [Operation: QUERY[0]]
Jan 13 22:05:36 sophie Sniffer: Question count: 1
Jan 13 22:05:36 sophie Sniffer: Answer record count: 0
Jan 13 22:05:36 sophie Sniffer: Athority record count: 0
Jan 13 22:05:36 sophie Sniffer: Addtional record count: 0
Jan 13 22:05:36 sophie Sniffer: (1).Question.name: .google.com
Jan 13 22:05:36 sophie Sniffer: (1).Question.type: A
```

### General Logs
``` html
Jan 13 22:07:28 sophie Sniffer: Conversation(1).(1)
Jan 13 22:07:28 sophie Sniffer: Source: 192.168.43.86:9956
Jan 13 22:07:28 sophie Sniffer: Desten: 192.168.43.255:9956 at [UDP]
Jan 13 22:07:28 sophie Sniffer: packet count: 2
Jan 13 22:07:28 sophie Sniffer: Total size: 348B
Jan 13 22:07:28 sophie Sniffer: Total net size: 264B
Jan 13 22:07:28 sophie Sniffer: Conversation(1).(2)
Jan 13 22:07:28 sophie Sniffer: Source: 192.168.43.86:9956
Jan 13 22:07:28 sophie Sniffer: Desten: 224.0.0.113:9956 at [UDP]
Jan 13 22:07:28 sophie Sniffer: packet count: 2
Jan 13 22:07:28 sophie Sniffer: Total size: 348B
Jan 13 22:07:28 sophie Sniffer: Total net size: 264B
```

# Testing options
To test code functionality there are two programs written in python which exchange HTTP packets. To test DNS packet sniffing you must run a local DNS server or just have a search which causes the flow of DNS packets to DNS server; you can also use `dig`.

## HTTP server
HTTP server is a simple HTTP server program which uses python libraries to handle requests and response them. the root folder of every working server is `./srcs`. To create a server you can use flowing command.
``` bash
sudo python http_server [IP to be used by server] [server port]
```
default value for IP:Port is `127.0.0.1:80`.

## HTTP client
This program could be used to send requests to any HTTP server and receive responses. The program also can be set on automatic mode to refresh information periodically. To use it run just run this command.
``` bash
python http_client.py [HTTP server IP][HTTP server port] [options]
# options are:
#        -m: to Disable manual refresh - the page could refresh by pressing Enter if this option is not used.
#        -a: to Enable Automatic refresh which is explained above.
#        --delay <seconds>: Automatic mode delay.
```
default value for IP:Port is `127.0.0.1:80`.

## General test
If you are not interested to do all of this to just testing a code you can run `launch.sh`. This bash script will compile, run, test, and show the output of code for you. The script needs some necessary inputs. So the correct form of use is
``` bash
sudo ./lanch.sh <device name> [options]
    # which options are:
    # -c --conversation         Displays conversations logs in a new termianl
    # -p --packets              Displays packets logs in a new terminal
    # -l --protocol-count       Displays number of packets exchanged over each protocols.
    # -t --tshark (l|c)         Uses tshark to make information about conversations and protocl count. this information are same as the output of -c and -l cause this option is just to test code.
    # -http --http-generator    Creates or just requests a HTTP sever to create HTTP packets manually. 
    # last option gives some extera parameters that are:
    #       --server IP         Create a local HTTP server on IP and port 80.
    #       --delay  SEC        HTTP requests are sent every SEC seconds.
    #       --url    URL/IP     The address of HTTP server. If you have a DNS server running you can add an A class record to it and use IP for IP of server and domain for url which makes you able to generate DNS packets too. but if are not using localhost just put domain as url in --url to generate DNSs.
```
In fact, the mentioned script creates an HTTP server and compiles and runs Sniffer then runs http_clients in number of "number of clients" and with "delay of each client". and after all reads `var/log/syslog` searching for logs.
