import sys
import json
import subprocess
import os
exec_name = "/home/nikita/memoire/dpdk_picoquic/dpdk_picoquicdemo"
cwd= "/home/nikita/memoire/dpdk_picoquic/"
args=json.loads(sys.argv[1])
cmd = 'sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH {exec_name} {eal} {args} {port}'.format(exec_name=exec_name,
                                                    eal=args["eal"],
                                                    args=args["args"],
                                                    port=args["port"])
print(cmd)
subprocess.call(cmd,shell=True,cwd=cwd)
