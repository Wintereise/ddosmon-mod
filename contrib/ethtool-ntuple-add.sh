#!/bin/sh

INTERFACE="eth0"

ethtool -U $INTERFACE flow-type ip4 src-ip $1 action -1
