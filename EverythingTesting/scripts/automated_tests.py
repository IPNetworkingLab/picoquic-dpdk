#!/usr/bin/env python3

from subprocess import Popen, PIPE

import json
import shlex

#Global variables
serverName = 'server'
clientName = 'client1'
process_name = 'dpdk_picoquicdemo'
dpdk1Client = 'dpdk -l 0-1 -a 0000:8a:00.1 -- -A 50:6b:4b:f3:7c:71'
dpdk1Server = 'dpdk -l 0-1 -a 0000:51:00.1 --'
nodpdk = 'nodpdk'


def dic_to_json(dic):
    return shlex.quote(json.dumps(dic))
    

def get_pid_process(host,name):
    cmds = ['ssh',host,'nohup','pidof',name]
    p = Popen(cmds, stdout=PIPE)
    return p.communicate()[0]

def kill_process(host,pid):
    cmds = ['ssh',host,'nohup','sudo kill',str(pid)]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def run_client(args):
    cmds = ['ssh', clientName,'python3','/home/nikita/memoire/dpdk_picoquic/EverythingTesting/scripts/client_for_tests.py',dic_to_json(args)]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def run_server(args):
    cmds = ['ssh', serverName,'python3','/home/nikita/memoire/dpdk_picoquic/EverythingTesting/scripts/server_for_tests.py',dic_to_json(args)]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def test_generic(argsClient,argsServer,isComparison):
    run_server(argsServer)
    client_process = run_client(argsClient)
    client_process.wait()
    pid = get_pid_process(serverName,process_name)
    intPid = int(pid)
    killing_process = kill_process(serverName,str(intPid))
    killing_process.wait()
    
    if isComparison:
        argsClientDpdk = argsClient.copy()
        argsClientDpdk["eal"] = nodpdk
        argsClientDpdk["output_file"].replace("dpdk","nodpdk")
        
        argsServerDpdk = argsServer.copy()
        argsServer["eal"] = dpdk1Server
        
        run_server(argsServerDpdk)
        client_process = run_client(argsClient)
        client_process.wait()
        pid = get_pid_process(serverName,process_name)
        intPid = int(pid)
        killing_process = kill_process(serverName,str(intPid))
        killing_process.wait()


if __name__ == "__main__":
    
    
    ##Throughput test
    clientArgsDpdk = {"eal" : dpdk1Client,
                  "args": "-D -N 10",
                  "output_file":"throughput_dpdk.txt",
                  "ip_and_port" : "10.100.0.2 5600",
                  "request" : "/2000000000",
                  "keyword" : "Mbps"}
       
    serverArgsDpdk = {"eal" : dpdk1Server,
                  "args" : "",
                  "port" : "-p 5600"}
    
    test_generic(clientArgsDpdk,serverArgsDpdk,True)
    
    ##Testing handshake
    # clientArgsDpdk = {"eal" : dpdk1Client,
    #               "args": "-H -D -a proxy -N 10",
    #               "output_file":"handshake_dpdk.txt",
    #               "ip_and_port" : "10.100.0.2 5600",
    #               "request" : "/100",
    #               "keyword" : "served"}   
    # serverArgsDpdk = {"eal" : dpdk1Server,
    #               "args" : "-a proxy",
    #               "port" : "-p 5600"}
    # serverArgsNoDpdk = serverArgsDpdk.copy()
    # serverArgsNoDpdk["eal"] = nodpdk
    # test_generic(clientArgsDpdk,serverArgsDpdk,True)
    
    
    

