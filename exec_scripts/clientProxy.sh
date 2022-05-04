
#!/bin/bash
sudo ./dpdk_picoquicdemo dpdk -l 2-3 -a 0000:8a:02.3 -a 0000:8a:02.4 --proc-type=primary --file-prefix=rte_1 --socket-mem=2000 -- -A 4e:da:17:3a:cb:83 -2 8a:37:d5:09:9b:31 -a proxy localhost 4443 /10000000000
#sudo ./dpdk_picoquicdemo dpdk -l 0-8 -a 0000:51:00.2 -a 0000:51:00.3 -a 0000:51:00.4 -a 0000:51:00.5 -a 0000:51:00.6 -a 0000:51:00.7 -a 0000:51:01.0 -a 0000:51:01.1  -- -A 50:6b:4b:f3:7c:70 -D localhost 4443 /1000000000
