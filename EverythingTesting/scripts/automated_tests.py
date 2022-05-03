#!/usr/bin/env python3

from subprocess import Popen, PIPE

import json
import shlex

#Global variables
serverName = 'server'
clientName = 'client1'
process_name = 'dpdk_picoquicdemo'
dpdk_1_client = 'dpdk -l 0-1 -a 0000:8a:00.1 -- -A 50:6b:4b:f3:7c:71'
dpdk_1_server = 'dpdk -l 0-1 -a -a 0000:51:00.1 --'
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
    print(args)
    cmds = ['ssh', clientName,'python3','/home/nikita/memoire/dpdk_picoquic/EverythingTesting/scripts/client_for_tests.py',dic_to_json(args)]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def run_server(args):
    print(args)
    cmds = ['ssh', serverName,'python3','/home/nikita/memoire/dpdk_picoquic/EverythingTesting/scripts/server_for_tests.py',dic_to_json(args)]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def test_cmp(argsClient,argsServer):
    run_server(argsServer)
    client_process = run_client(argsClient)
    client_process.wait()
    pid = get_pid_process(serverName,process_name)
    intPid = int(pid)
    killing_process = kill_process(serverName,str(intPid))
    killing_process.wait()
    
    argsClientDpdk = argsClient.copy()
    argsClientDpdk["eal"] = nodpdk
    argsClientDpdk["output_file"].replace("dpdk","nodpdk")
    
    argsServerDpdk = argsServer.copy()
    argsServer["eal"] = dpdk_1_server
    
    run_server(argsServerDpdk)
    client_process = run_client(argsClient)
    client_process.wait()
    pid = get_pid_process(serverName,process_name)
    intPid = int(pid)
    killing_process = kill_process(serverName,str(intPid))
    killing_process.wait()


if __name__ == "__main__":
    
    
    clientArgsDpdk = {"eal" : dpdk_1_client,
                  "args": "-H -D -a proxy -N 10",
                  "output_file":"handshake_dpdk",
                  "ip_and_port" : "10.100.0.2 5600",
                  "request" : "/100"}   
    serverArgsDpdk = {"eal" : dpdk_1_server,
                  "args" : "-a proxy",
                  "port" : 5600}
    serverArgsNoDpdk = serverArgsDpdk.copy()
    serverArgsNoDpdk["eal"] = nodpdk
    test_cmp(clientArgsDpdk,serverArgsDpdk)
    
    
    

