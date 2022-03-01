import os
import sys



os.chdir("/home/nikita/memoire/dpdk_picoquic/")
server_core = sys.argv[1]
nb_of_iteration = int(sys.argv[2])

mycommand = ("sudo /home/nikita/memoire/dpdk_picoquic/dpdk_picoquicdemo -l 0-8 "
            "-a 0000:51:00.2 -a 0000:51:00.3 -a 0000:51:00.4 -a 0000:51:00.5 -a 0000:51:00.6 -a 0000:51:00.7 -a 0000:51:01.0 -a 0000:51:0.1 "
            "-- -A 50:6b:4b:f3:7c:70 -D localhost 4443 /10000000"
            "| grep Mbps >> EverythingTesting/output_8client_{}servercore.txt")

for i in range(nb_of_iteration):
    os.system(mycommand.format(server_core))
