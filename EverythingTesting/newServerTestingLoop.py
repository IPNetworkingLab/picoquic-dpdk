
import os
import sys



server_core = sys.argv[1]
#needed to make everything work
os.chdir("/home/nikita/memoire/dpdk_picoquic") 
mycommand = ("sudo /home/nikita/memoire/dpdk_picoquic/dpdk_picoquicdemo -l 0-{} -a 0000:51:00.0 -- -p 4443".format(str(server_core)))
os.system(mycommand)



