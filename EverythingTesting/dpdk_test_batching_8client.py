import os
import sys



os.chdir("/home/nikita/memoire/dpdk_picoquic/")
nb_of_iteration = int(sys.argv[1])
file_name = int(sys.argv[2])
size = 1000000000

mycommand = ("sudo /home/nikita/memoire/dpdk_picoquic/dpdk_picoquicdemo dpdk -l 0-8 -a 0000:51:00.2 -a 0000:51:00.3 -a 0000:51:00.4 -a 0000:51:00.5 -a 0000:51:00.6 -a 0000:51:00.7 -a 0000:51:01.0 -a 0000:51:01.1 -- -A 50:6b:4b:f3:7c:70 -N {} -D localhost 4443 /{}"
            "| grep Mbps >> EverythingTesting/output_tp_dpdk_8_{}.txt")

os.system(mycommand.format(nb_of_iteration,size,file_name))