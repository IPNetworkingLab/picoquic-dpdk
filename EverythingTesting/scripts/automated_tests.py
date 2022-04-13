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

def tp_test_generic(filename1,args1,usedpdk1,filename2,args2,usedpdk2,iterations):
    run_server(usedpdk1," ")
    client_process = run_client_generic(iterations,filename1,args1,usedpdk1)
    client_process.wait()
    pid = get_pid_process(serverName,process_name)
    intPid = int(pid)
    killing_process = kill_process(serverName,str(intPid))
    killing_process.wait()
    
    run_server(usedpdk2," ")
    client_process = run_client_generic(iterations,filename2,args2,usedpdk2)
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
    # tp_test_generic("dpdk_tp","",1,"nodpdk_tp","",0,10)
    # tp_test_generic("dpdk_tp_enc","",1,"nodpdk_tp_enc","",0,10)
    # tp_test_generic("dpdk_chacha","",1,"nodpdk_chacha","",0,5)
    tp_test_generic("copyv2","",1,"nopyv2","-D",1,10)
    
    

