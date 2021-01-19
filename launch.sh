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
    echo "       URL‌s could be replaced by IP, code is compatible, so correct tense is --url [URL/IP]"
    echo "                                                                                          "
    echo "       -http --HTTP-generator [--server IP] [--delay seconds] [--url URL]   If this option is passed program generates some HTTP packets to test code functionality"
    echo "                                                              --delay is used to control packets congestion"
    echo "                                                              use --server to run an HTTP server."
    echo "                                                              "
    echo "       -s --separated                                         to compile code in such a way that prints tag before logs for example, Sniffer: (status), instead of just Sniffer:"
    echo "                                                              Note that if you ues any of -c or -t this option will be set automatically"   
    echo "       -t --tshark                                            Program runs tshark and stores conversations in ./General-Logs-test-reslut"
    echo "       -v --version                                           Shows code version"
    echo "       -h --help                                              Help page"
}

http_packet=false
logs_print=false
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
            wireshark_cmp=true
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
        --* | -* | *)
            echo "Warning: Ignoring invalid argument" "$1"
            ;;
        esac
        shift
done

# compile files
make clean > /dev/null

if $logs_print || $status_print || $seperated_comp
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

trap handle_sigint SIGINT
function handle_sigint
{
    for process in $(jobs -p)
    do
        kill $process 2> /dev/null
    done
}

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
    wireshark_conv &
    touch ./wireshark_output.pcap
    chmod o=rw ./wireshark_output.pcap
    tshark -i $device_name -w wireshark_output.pcap -F pcap -Q &
    gnome-terminal --window --title="Tshark - Conversations" -- bash -c "tail -f ./all.txt" &
fi

if $status_print
then
    gnome-terminal --window --title="Sniffer - conversations" -- bash -c "tail -f /var/log/syslog | grep 'Sniffer: (status)'" &
fi

if $logs_print
then
    gnome-terminal --window --title="Sniffer - packets" -- bash -c "tail -f /var/log/syslog | grep 'Sniffer: (packet)'" &
fi

./sniffer $device_name
rm -f all.txt wireshark_output.pcap
exit