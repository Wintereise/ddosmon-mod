#!/bin/sh

INTERFACE="eth0"

ruleno() {
	ethtool -u $INTERFACE | grep -B 2 -h "Src IP addr: $1" | head -n 1 | awk '{ print $2 }'
}

RULE=$(ruleno $1)

ethtool -U $INTERFACE delete $RULE
