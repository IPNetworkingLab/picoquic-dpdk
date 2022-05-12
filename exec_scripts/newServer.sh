#!/bin/bash
sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH ./dpdk_picoquicdemo dpdk -l 0-1 -a 0000:51:00.1 -- -p 4443
