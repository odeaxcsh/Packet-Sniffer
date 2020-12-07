#!/bin/bash
make
sudo python http_server.py >/dev/null 2>&1 &

for((i=0; i<"$1"; i++))
do
    python http_client.py -a -m --delay "$2" >/dev/null 2>&1 &
done

./sniffer lo &
tail -f /var/log/syslog | grep 'Sniffer'