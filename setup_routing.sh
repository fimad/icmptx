#!/bin/bash

if [ "$#" -ne "2" ]; then
  echo "usage: host device"
  exit
fi

host=$1
dev=$2

real_gateway=`netstat -nr | egrep '^0.0.0.0' | sed -r 's/^[0-9\.]+\s+([0-9\.]+)\s+.+$/\1/g'`
route add -host $host gw $real_gateway dev $dev
route del default
route add default gw 10.0.3.1 tun0
