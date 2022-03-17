import os
import sys



os.chdir("/home/nikita/memoire/dpdk_picoquic/")
nb_of_iteration = int(sys.argv[1])
size = 1000000000

mycommand = ("sudo /home/nikita/memoire/dpdk_picoquic/dpdk_picoquicdemo nodpdk -H -D 10.200.0.2 4443 /{}"
            "| grep served >> EverythingTesting/output_handshakes_van.txt")
for i in range(nb_of_iteration):
    os.system(mycommand.format(size))
