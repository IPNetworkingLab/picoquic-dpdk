
import os
import sys



os.chdir("/home/nikita/memoire/dpdk_picoquic/")
server_core = sys.argv[1]

mycommand = ("sudo /home/nikita/memoire/dpdk_picoquic/dpdk_picoquicdemo -l 0-{} -a 0000:51:00.0 -- -p 4443".format(server_core))
os.system(mycommand)



