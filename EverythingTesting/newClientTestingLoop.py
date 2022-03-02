import os
import sys



os.chdir("/home/nikita/memoire/dpdk_picoquic/")
server_nb_core = sys.argv[1]
size_of_file = sys.argv[2]
file_name = sys.argv[3]
nb_of_iteration = int(sys.argv[4])

mycommand = ("sudo /home/nikita/memoire/dpdk_picoquic/dpdk_picoquicdemo -l 0-8 "
            "-a 0000:51:00.2 -a 0000:51:00.3 -a 0000:51:00.4 -a 0000:51:00.5 -a 0000:51:00.6 -a 0000:51:00.7 -a 0000:51:01.0 -a 0000:51:01.1 "
            "-- -A 50:6b:4b:f3:7c:70 -N {} -D localhost 4443 /{}"
            "| grep Mbps >> EverythingTesting/output_{}_{}.txt")

os.system(mycommand.format(nb_of_iteration,size_of_file,file_name,server_nb_core))
