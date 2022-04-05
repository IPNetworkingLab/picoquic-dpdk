import os
import sys

os.chdir("/home/nikita/memoire/dpdk_picoquic/")
mycommand = ("sudo ./dpdk_picoquicdemo dpdk -l 0-1 -a 0000:51:00.0 -- -p 4443")
os.system(mycommand)