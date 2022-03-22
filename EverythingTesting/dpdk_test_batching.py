import os
import sys



os.chdir("/home/nikita/memoire/dpdk_picoquic/")
nb_of_iteration = int(sys.argv[1])
batching = int(sys.argv[2])
gB = 10**9
size = 20*gB

mycommand = ("sudo /home/nikita/memoire/dpdk_picoquic/dpdk_picoquicdemo dpdk -l 0-1 -a 0000:51:00.0 -- -@ {} -A 50:6b:4b:f3:7c:70 -N {} -D localhost 4443 /{}"
            "| grep Mbps >> EverythingTesting/output_tp_dpdk_batching_{}.txt")

os.system(mycommand.format(batching,nb_of_iteration,size,batching))