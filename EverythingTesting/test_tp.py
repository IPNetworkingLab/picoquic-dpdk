import os
import sys



os.chdir("/home/nikita/memoire/dpdk_picoquic/")
nb_of_iteration = int(sys.argv[1])
size = 1000000000

mycommand = ("sudo /home/nikita/memoire/dpdk_picoquic/dpdk_picoquicdemo nodpdk -N {} -D 10.200.0.2 4443 /{}"
            "| grep Mbps >> EverythingTesting/output_tp_van.txt")

os.system(mycommand.format(nb_of_iteration,size))

