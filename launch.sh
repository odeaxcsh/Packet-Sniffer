#!/bin/bash

function print_help
{
    echo "Program Usage:"
    echo "<device name> [options]"
    echo "Options are:"
    echo "       outputs are displayed in a new terminal."
    echo "                                               "
    echo "       -c --conversations                                     To display general logs [Conversations detail]"
    echo "       -p --packets                                           To display packets details [HTTP‌ and DNS‌ packets detail]"
    echo "                                                              "
    echo "       -dns --DNS‌-generator [--url URL]                       If this option is used program generates some DNS packets to test code functionality"
    echo "                                                              If url is not set then code uses pishtazhttp.xyz or google.com according to if sniffing device is loop back or is not"      
    echo "       -http --HTTP-generator [--delay seconds]               If this option is passed program generates some HTTP packets to test code functionality"
    echo "                                                              --delay is used to control packets congestion"
    echo "                                                              "
    echo "       -t --tshark                                            Program runs tshark and stores conversations in ./General-Logs-test-reslut"
    echo "       -v --version                                           Shows code version"
    echo "       -h --help                                              Help page"
}

dns_packet=false
http_packet=false
logs_print=false
status_print=false
wireshark_cmp=false

device_name="$1"
if [[ $device_name = -* ]]
then
    echo "First argument must be device name."
    echo "Warning: Using loopback"
    device_name="lo"
else
    shift
fi

while test $# -gt 0
do
    case "$1" in
        --conversations | -c)
            status_print=true
            ;;
        --packets | -p)
            logs_print=true
            ;;
        --HTTP-genrator | -http)
            http_packet=true
            if [[ "$2" = --delay ]]
            then
                http_packet_delay="$3"
                shift 2
            else
                http_packet_delay=15
            fi
            ;;
        --DNS-generator | -dns)
            dns_packet=true
            if [[ "$2" = --url ]]
            then
                dns_url="$3"
                shift
            else
                [[ device_name = lo ]] && dns_url="pishtazhttp.xyz" || dns_url="google.com"
            fi
            ;;
        --tshark | -t)
            wireshark_cmp=true
            ;;
        --help | -h)
            print_help
            exit
            ;;
        --version | -v)
            echo "v3.4"
            echo "written by Odeaxcsh"
            echo "github.com/odeaxcsh/packet-sniffer"
            exit
            ;;
        --* | -* | *)
            echo "Warning: Ignoring invalid argument" "$1"
            ;;
        esac
        shift
done

make clean > /dev/null

if $status_print or $status_print
then
    make seperated > /dev/null
else
    make normal > /dev/null
fi

if $dns_packet and curl --output /dev/null --silent --head --fail "$dns_url"
then
    is_dns_url_valid=true
else
    is_dns_url_valid=false
    if $dns_packet
    then
        echo "Warning: Entered URL is not valid. If you sure you want to continue press Enter"
        read
    fi
fi

#RUN‌ packet generators
function send_requests
{
    while true
    do 
    sleep "$3"
    $1 "$2" > /dev/null
    done
}

#if we need both of this packets and server is available then just send packets to that url and this will make everything work
if $is_dns_url_valid and‌ $http_packet
then
    send_requests http "$dns_url" "$http_packet_delay"
    echo "$is_dns_url_valid"
else
    if $http_packet
    then
        if [[ $device_name = lo ]]
        then
            python http_server.py 127.1.1.80 80 >/dev/null 2>&1 &
            python http_client.py -a -m --delay "$http_packet_delay" 127.1.1.80 80 >/dev/null 2>&1 &
        else
            send_requests http eu.httpbin.org $http_packet_delay
        fi
    elif $dns_packet
    then
        send_requests dig $dns_url 5
    fi
fi

if $status_print
then
    gnome-terminal --window --title="Sniffer - conversations" -- bash -c "tail -f /var/log/syslog | grep 'Sniffer: (status)'" &
fi

if $logs_print
then
    gnome-terminal --window --title="Sniffer - packets" -- bash -c "tail -f /var/log/syslog | grep 'Sniffer: (packet)'" &
fi

function wireshark_conv
{
    counter=0
    while true
    do
        ++$counter
        tshark -i $device_name -z conv,udp -z conv,tcp -a duration:30 -Q 1> "./tmp/${counter}.txt"
        cat "./tmp/${counter}.txt" >> "./tmp/all.txt"
    done
}


if $wireshark_cmp
then
    rm -f ./tmp/*
    touch ./tmp/all.txt
    wireshark_conv &
    gnome-terminal --window --title="Tshark - Conversations" -- bash -c "tail -f ./tmp/all.txt" &
fi

trap handle_sigint SIGINT
function handle_sigint
{
    for process in $(jobs -p)
    do
        kill $process > /dev/null
    done
}

./sniffer $device_name
rm -f ./tmp/*
exit