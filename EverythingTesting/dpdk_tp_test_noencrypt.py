import os
import sys



os.chdir("/home/nikita/memoire/dpdk_picoquic/")
nb_of_iteration = int(sys.argv[1])
size = 10000000000

mycommand = ("sudo /home/nikita/memoire/dpdk_picoquic/dpdk_picoquicdemo dpdk -l 0-1 -a 0000:51:00.1 -- -A 50:6b:4b:f3:7c:70 -N {} -D localhost 4443 /{}"
            "| grep Mbps >> EverythingTesting/output_tp_dpdk_noencrypt.txt")

os.system(mycommand.format(nb_of_iteration,size))