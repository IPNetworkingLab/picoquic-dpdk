#!/usr/bin/env python3

import time
from subprocess import Popen, PIPE


serverName = 'server'
clientName = 'client1'
process_name = 'dpdk_picoquicdemo'

def get_pid_process(host,name):
    cmds = ['ssh',host,'nohup','pidof',name]
    p = Popen(cmds, stdout=PIPE)
    return p.communicate()[0]

def kill_process(host,pid):
    cmds = ['ssh',host,'nohup','sudo kill',str(pid)]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def run_client_generic(iterations,filename,args,isdpdk):
    cmds = ['ssh', clientName,'python3','/home/nikita/memoire/dpdk_picoquic/EverythingTesting/scripts/tp_generic.py',str(iterations),filename,args,str(isdpdk)]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def run_server(isdpdk,args):
    cmds = ['ssh', serverName,'python3','/home/nikita/memoire/dpdk_picoquic/EverythingTesting/scripts/serverTesting.py',str(isdpdk),args]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def tp_test_generic(filename1,args1,filename2,args2,iterations):
    #dpdk throughput
    # run_server(1," ")
    # client_process = run_client_generic(iterations,filename1,args1,1)
    # client_process.wait()
    # pid = get_pid_process(serverName,process_name)
    # intPid = int(pid)
    # killing_process = kill_process(serverName,str(intPid))
    # killing_process.wait()
    
    #nodpdk throughput
    run_server(1," ")
    client_process = run_client_generic(iterations,filename2,args2,1)
    client_process.wait()
    pid = get_pid_process(serverName,process_name)
    intPid = int(pid)
    killing_process = kill_process(serverName,str(intPid))
    killing_process.wait()


if __name__ == "__main__":
    # throughput_test()
    # web_test()
    # handshake_test()
    #batching_test_dpdk()
    #copy vs nocopy callback
    tp_test_generic("nocopy","-D","copy", " ",10)

