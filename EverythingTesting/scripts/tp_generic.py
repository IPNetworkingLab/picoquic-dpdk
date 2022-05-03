import os
import sys


os.chdir("/home/nikita/memoire/dpdk_picoquic/")
print("hello")
nb_of_iteration = int(sys.argv[1])
filename = sys.argv[2]
isdpdk = sys.argv[3]
args = sys.argv[4:]
print(args)
size = 20000000000

dpdk = "dpdk -l 0-1 -a 0000:8a:00.1 -- -A 50:6b:4b:f3:7c:71"
nodpdk = "nodpdk"
setup = ""

if isdpdk == 0:
    setup = nodpdk
else:
    setup = dpdk



mycommand = ("sudo /home/nikita/memoire/dpdk_picoquic/dpdk_picoquicdemo {} -N {} {} 10.100.0.2 5600 /{}"
            "| grep Mbps >> EverythingTesting/data/output_{}.txt")

os.system(mycommand.format(setup,nb_of_iteration,args,size,filename))