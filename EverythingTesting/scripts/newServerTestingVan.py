import os
import sys

os.chdir("/home/nikita/memoire/dpdk_picoquic/")
mycommand = ("sudo ./dpdk_picoquicdemo nodpdk -p 4443")
os.system(mycommand)