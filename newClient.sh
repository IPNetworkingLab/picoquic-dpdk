#!/bin/bash
# sudo ./dpdk_picoquicdemo -l 0 -a 0000:51:00.0 -- -A 50:6b:4b:f3:7c:70 -D localhost 4443 /10000000000

sudo ./dpdk_picoquicdemo -l 0-8 -a 0000:51:00.2 -a 0000:51:00.3 -a 0000:51:00.4 -a 0000:51:00.5 -a 0000:51:00.6 -a 0000:51:00.7 -a 0000:51:01.0 -a 0000:51:01.1  -- -A 50:6b:4b:f3:7c:70 -D localhost 4443 /100000000000
