import os
import sys



os.chdir("/home/nikita/memoire/dpdk_picoquic/")
nb_of_iteration = int(sys.argv[1])
size = 10000000000

mycommand = ("sudo /home/nikita/memoire/dpdk_picoquic/dpdk_picoquicdemo dpdk -l 0-1 -a 0000:51:00.0 -- -A 50:6b:4b:f3:7c:70 -H -D localhost 4443 /{}"
            " >> EverythingTesting/output_handshakes_dpdk.txt")
for i in range(nb_of_iteration):
    os.system(mycommand.format(size))
