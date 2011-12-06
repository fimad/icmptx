#!/bin/bash
./icmptx -s $@ > client.log &
sleep 1
ifconfig tun0 10.0.3.2 netmask 255.255.255.0
