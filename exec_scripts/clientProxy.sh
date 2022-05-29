
#!/bin/bash
sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH ./dpdk_picoquicdemo --dpdk -l 2-3 -a 0000:8a:00.6 -a 0000:8a:00.7 --proc-type=primary --file-prefix=rte_1 --socket-mem=2000 -- -A 52:9f:20:28:0b:c2 -2 8a:37:d5:09:9b:31 -* 1 -a proxy localhost 4443 /10000000000
#sudo ./dpdk_picoquicdemo dpdk -l 0-8 -a 0000:51:00.2 -a 0000:51:00.3 -a 0000:51:00.4 -a 0000:51:00.5 -a 0000:51:00.6 -a 0000:51:00.7 -a 0000:51:01.0 -a 0000:51:01.1  -- -A 50:6b:4b:f3:7c:70 -D localhost 4443 /1000000000
