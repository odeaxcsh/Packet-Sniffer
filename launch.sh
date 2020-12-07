#!/bin/bash
make clean
make
sudo python http_server.py 127.1.1.0 80 >/dev/null 2>&1 &

for((i=0; i<"$1"; i++))
do
    sleep .01
    python http_client.py -a -m --delay "$2" 127.1.1.0 80 >/dev/null 2>&1 &
done

sudo ./sniffer lo &

function handle_sigint()
{
    for process in $(jobs -p)
    do
        sudo kill $process
    done
}

trap handle_sigint SIGINT

tail -f /var/log/syslog | grep 'Sniffer'