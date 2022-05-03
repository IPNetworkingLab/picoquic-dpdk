import sys
import json
import subprocess

exec_name = "/home/nikita/memoire/dpdk_picoquic/dpdk_picoquicdemo"

print(sys.argv[1])
args=json.loads(sys.argv[1])

mycommand = ("sudo ./dpdk_picoquicdemo {} {} -p 5600")
subprocess.call(['sudo',exec_name,args["eal"],args["args"],args["port"]])