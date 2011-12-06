#!/bin/bash
./icmptx -s $@ > server.log &
sleep 1
ifconfig tun0 10.0.3.1 netmask 255.255.255.0
