#!/bin/bash
sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH ./dpdk_picoquicdemo --dpdk -l 0-1 -a 0000:51:00.1 -- -d 10.100.0.2 -* 128 -@ 128 -p 4443 -1
