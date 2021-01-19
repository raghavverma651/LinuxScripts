#!/bin/bash
if ping -q -c 1 -W 1 8.8.8.8 >/dev/null; then
    cat /proc/net/arp > /root/Downloads/validarp
    sudo python3 /root/Downloads/arpdetect.py
else
    echo "Internet is not working. First connect to the internet"
    echo "Waiting for connection"
    sudo /root/Downloads/runagain.sh
fi       


