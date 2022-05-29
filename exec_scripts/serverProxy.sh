#!/bin/bash
sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH ./dpdk_picoquicdemo --dpdk -l 4-5 -a 0000:8a:01.0 -a 0000:8a:01.1 --proc-type=primary --file-prefix=rte_2 --socket-mem=2000 -- -2 32:af:e5:33:4f:ac -a proxy -* 1 -p 4443 
