import os
import sys


os.chdir("/home/nikita/memoire/dpdk_picoquic/")
nb_of_iteration = int(sys.argv[1])
filename = sys.argv[2]
args=""
isdpdk = 0
if len(sys.argv)==4:
    isdpdk = int(sys.argv[3])
else:
    isdpdk = int(sys.argv[4])
    args = sys.argv[3]
size = 20000000000

dpdk = "dpdk -l 0-1 -a 0000:51:00.1 -- -A 50:6b:4b:f3:7c:70"
nodpdk = "nodpdk"
setup = ""

if isdpdk == 0:
    setup = nodpdk
else:
    setup = dpdk



mycommand = ("sudo /home/nikita/memoire/dpdk_picoquic/dpdk_picoquicdemo {} -N {} {} 10.100.0.2 5600 /{}"
            "| grep Mbps >> EverythingTesting/data/output_{}.txt")

os.system(mycommand.format(setup,nb_of_iteration,args,size,filename))