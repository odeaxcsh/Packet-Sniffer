#!/bin/bash
make clean
make
python http_server.py 127.1.1.80 80 >/dev/null 2>&1 &

for((i=0; i<"$1"; i++))
do
    sleep .01
    python http_client.py -a -m --delay "$2" pishtazhttp.xyz >/dev/null 2>&1 &
done

./sniffer lo &

function handle_sigint()
{
    for process in $(jobs -p)
    do
        kill $process
    done
}

trap handle_sigint SIGINT

tail -f /var/log/syslog | grep 'Sniffer'