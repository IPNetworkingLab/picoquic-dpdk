#!/bin/bash
sudo valgrind ./dpdk_picoquicdemo -l 0-4 -a 0000:51:00.2 -a 0000:51:00.3 -a 0000:51:00.4 -a 0000:51:00.5 -- -A 50:6b:4b:f3:7c:70 -D localhost 4443 /10000000000