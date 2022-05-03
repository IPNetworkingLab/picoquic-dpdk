import os
import sys

print("serverTesting")
os.chdir("/home/nikita/memoire/dpdk_picoquic/")
dpdk = "dpdk -l 0-1 -a -a 0000:51:00.1 -- "
nodpdk = "nodpdk "
isdpdk = int(sys.argv[1])
args = sys.argv[2:]
setup = ""
if isdpdk == 1:
    setup = dpdk
else:
    setup = nodpdk
mycommand = ("sudo ./dpdk_picoquicdemo {} {} -p 5600")
os.system(mycommand.format(setup,args))