import sys
import json
import subprocess
import os
execName = "/home/nikita/memoire/dpdk_picoquic/dpdk_picoquicdemo"
output_file_prefix = "/home/nikita/memoire/dpdk_picoquic/EverythingTesting/data/"
cwd = "/home/nikita/memoire/dpdk_picoquic"
args=json.loads(sys.argv[1])
cmd = 'sudo {execName} {eal} {args} {ip_and_port} {request} | grep {keyword} >> {output_file}'.format(
                                                            execName=execName,
                                                            args=args['args'],
                                                            eal=args['eal'],
                                                            ip_and_port=args['ip_and_port'],
                                                            request=args["request"],
                                                            keyword=args["keyword"],
                                                            output_file = output_file_prefix + args["output_file"])

print(cmd)
subprocess.call(cmd,shell=True,cwd=cwd)