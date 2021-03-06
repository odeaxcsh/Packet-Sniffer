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
    echo "       -l --protocol-count                                    To display packet count classified by protocol"
    echo "                                                              "
    echo "       URL‌s could be replaced by IP, code is compatible, so correct tense is --url [URL/IP]"
    echo "                                                                                          "
    echo "       -http --HTTP-generator [--server IP] [--delay seconds] [--url URL]   If this option is passed program generates some HTTP packets to test code functionality"
    echo "                                                              --delay is used to control packets congestion"
    echo "                                                              use --server to run an HTTP server."
    echo "                                                              "
    echo "       -s --separated                                         to compile code in such a way that prints tag before logs for example, Sniffer: (status), instead of just Sniffer:"
    echo "                                                              Note that if you ues any of -c or -t this option will be set automatically"   
    echo "       -t [parametrs space seperated] --tshark                With this option he program runs tshark to generate information simultaneously. parameters define which part of information must be genrated"
    echo "                                                              Parameters are c for conversations and p l for protocol count"
    echo "       -v --version                                           Shows code version"
    echo "       -h --help                                              Help page"
}

packet_count=false
http_packet=false
logs_print=false
wireshark_cmp_l=false
status_print=false
wireshark_cmp=false
seperated_comp=false
create_http_server=false
http_packet_delay=15
http_url="127.1.1.80"

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

            if [[ "$2" = --server ]]
            then
                create_http_server=true
                http_server_ip="$3"
                shift 2
            fi

            if [[ "$2" = --delay ]]
            then
                http_packet_delay="$3"
                shift 2
            fi

            if [[ "$2" = --url ]]
            then 
                http_url="$3"
                shift 2
            fi
            ;;

        --tshark | -t)
            while [[ "$2" =~ ^(l|c) ]] 
            do
                if [[ "$2" = c ]]
                then
                    wireshark_cmp=true
                elif [[ "$2" = l ]]
                then
                    wireshark_cmp_l=true
                else
                    echo "Invalid parameter for -t option. Ignoring: $2"
                fi
                shift
            done
            ;;

        --separated | -s)
            seperated_comp=true
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

        -l | --protocol-count)
            packet_count=true
            ;;
        
        --* | -* | *)
            echo "Warning: Ignoring invalid argument" "$1"
            ;;
        
        esac
        shift
done

# compile files
make clean > /dev/null

if $logs_print || $status_print || $seperated_comp || $packet_count
then
    make seperated  > /dev/null
else
    make normal > /dev/null
fi

if $create_http_server
then
    if [[ $device_name != lo ]]
    then
        echo "Creating HTTP‌ server will not effct on non-loop back network interfaces"
        echo "Do you want to Continue? [Y/other keys]"
        read -p "" input && [[ $input == [yY] || $input == [yY][eE][sS] ]] &&  python http_server.py $http_url 80 >/dev/null 2>&1 &
    else
        python http_server.py $http_server_ip 80 >/dev/null 2>&1 &
    fi
fi

# url check
if $http_packet
then
    if curl --output /dev/null --silent --head --fail $http_url
    then
        is_url_valid=true
    else
        is_url_valid=false
        echo "Warning: HTTP server at ${http_url} couldn't be reached. If you sure you want to continue enter y"
        read -p "" input && [[ $input == [yY] || $input == [yY][eE][sS] ]] && is_url_valid=true
    fi
fi

#if we need both of this packets and server is available then just send packets to that url and this will make everything work
if $http_packet && $is_url_valid
then
    python http_client.py -a -m --delay $http_packet_delay $http_url 80 >/dev/null 2>&1 &
fi

function kill_all
{
    for process in $(jobs -p)
    do
        kill $process 2> /dev/null
    done
}
trap kill_all SIGINT

function wireshark_conv
{
    while true
    do
        sleep 30
        tshark -r ./wireshark_output.pcap -z conv,udp -z conv,tcp -Q 1>> "./all.txt"
    done
}

if $wireshark_cmp
then
    touch ./all.txt
    wireshark_c &
    touch ./wireshark_output.pcap
    chmod o=rw ./wireshark_output.pcap
    tshark -i $device_name -w wireshark_output.pcap -F pcap -Q &
    gnome-terminal --window --title="Tshark - Conversations" -- bash -c "tail -f ./all.txt" &
fi

if $wireshark_cmp_l
then
    tshark -i $device_name -qz io,stat,60,"(tcp.port==80)","(udp.port==53)","(tcp.port==21)","(tcp.port==443)","(tcp.port==123)" > ./logs.txt &
fi

if $status_print
then
    gnome-terminal --window --title="Sniffer - conversations" -- bash -c "tail -f /var/log/syslog | grep 'Sniffer: (status)'" &
fi

if $logs_print
then
    gnome-terminal --window --title="Sniffer - packets" -- bash -c "tail -f /var/log/syslog | grep 'Sniffer: (packet)'" &
fi

if $packet_count
then
    gnome-terminal --window --title="Sniffer - Packet count" -- bash -c "tail -f /var/log/syslog | grep 'Sniffer: (Protocol count)'" &
fi

./sniffer $device_name
cat ./logs.txt
rm -f ./logs.txt
rm -f all.txt wireshark_output.pcap log.txt
kill_all
make clean
exit