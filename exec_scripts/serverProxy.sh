#!/bin/bash
sudo ./dpdk_picoquicdemo dpdk -l 4-5 -a 0000:8a:02.5 -a 0000:8a:02.6 --proc-type=primary --file-prefix=rte_2 --socket-mem=2000 -- -2 4e:ee:af:42:01:e5 -a proxy -p 4443 
