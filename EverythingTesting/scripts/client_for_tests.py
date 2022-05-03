import sys
import json
import subprocess

execName = "/home/nikita/memoire/dpdk_picoquic/dpdk_picoquicdemo"
output_file_prefix = "/home/nikita/EverythingTesting/data"

print(sys.argv[1])
args=json.loads(sys.argv[1])
print(args)
subprocess.call(['sudo',execName,args["eal"],args["args"],args["ip_and_port"],args["request"],">>", output_file_prefix+args["output_file"]])