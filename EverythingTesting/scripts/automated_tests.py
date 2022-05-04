#!/usr/bin/env python3

from subprocess import Popen, PIPE

import json
import shlex

def retrieve_cards():
    cards = open('cards.txt', 'r')
    lines = cards.readlines()
    counter = 0
    ret = ''
    for line in lines:
        if(counter < 4):
            counter +=1
        else:
            line_as_array = line.split()
            card_id = line_as_array[0]
            ret += '-a 0000:{} '.format(card_id)
    return ret

#Global variables
serverName = 'server'
clientName = 'client1'
process_name = 'dpdk_picoquicdemo'
dpdk1Client = 'dpdk -l 0-1 -a 0000:8a:00.1 -- -A 50:6b:4b:f3:7c:71'
dpdk8Client = 'dpdk -l 0-16 {} -- -A 50:6b:4b:f3:7c:71'.format(retrieve_cards())
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
        argsClientNoDpdk = argsClient.copy()
        argsClientNoDpdk["eal"] = nodpdk
        argsClientNoDpdk["output_file"] = argsClientNoDpdk["output_file"].replace("dpdk","nodpdk")
        
        argsServerNoDpdk = argsServer.copy()
        argsServerNoDpdk["eal"] = nodpdk
        
        run_server(argsServerNoDpdk)
        client_process = run_client(argsClientNoDpdk)
        client_process.wait()
        pid = get_pid_process(serverName,process_name)
        intPid = int(pid)
        killing_process = kill_process(serverName,str(intPid))
        killing_process.wait()

def test_server_scaling():
    
    clientArgs = {"eal" : dpdk8Client,
                  "args": "-D -N 10",
                  "output_file":"handshake_dpdk.txt",
                  "ip_and_port" : "10.100.0.2 5600",
                  "request" : "/10000000000",
                  "keyword" : "Mbps"}   
    serverArgs = {"eal" : dpdk1Server,
                  "args" : "",
                  "port" : "-p 5600"}
    for i in range(1,17):
        serverArgs["eal"] = 'dpdk -l 0-{} -a 0000:51:00.1 --'.format(i)
        clientArgs["output_file"] = "handshake_dpdk.txt" + "_{}".format(str(i))
        test_generic(clientArgs,serverArgs,False)
    
    
def test_throughput():
    ##Throughput test
    clientArgsDpdk = {"eal" : dpdk1Client,
                  "args": "-D -N 10",
                  "output_file":"throughput_dpdk.txt",
                  "ip_and_port" : "10.100.0.2 5600",
                  "request" : "/20000000000",
                  "keyword" : "Mbps"}
       
    serverArgsDpdk = {"eal" : dpdk1Server,
                  "args" : "",
                  "port" : "-p 5600"}
    
    test_generic(clientArgsDpdk,serverArgsDpdk,True)
    
    
def test_handshake():
    #Testing handshake
    clientArgsDpdk = {"eal" : dpdk1Client,
                  "args": "-H -D",
                  "output_file":"handshake_dpdk.txt",
                  "ip_and_port" : "10.100.0.2 5600",
                  "request" : "/100",
                  "keyword" : "served",
                  "reps" : 10}   
    serverArgsDpdk = {"eal" : dpdk1Server,
                  "args" : "",
                  "port" : "-p 5600"}
    test_generic(clientArgsDpdk,serverArgsDpdk,True)
    
def test_request():
    #Testing requests
    clientArgsDpdk = {"eal" : dpdk1Client,
                  "args": "-3 -D -N 10",
                  "output_file":"request_dpdk.txt",
                  "ip_and_port" : "10.100.0.2 5600",
                  "request" : "*10000000:/100000",
                  "keyword" : "served"}   
    serverArgsDpdk = {"eal" : dpdk1Server,
                  "args" : "",
                  "port" : "-p 5600"}
    serverArgsNoDpdk = serverArgsDpdk.copy()
    serverArgsNoDpdk["eal"] = nodpdk
    test_generic(clientArgsDpdk,serverArgsDpdk,True)
    
    

if __name__ == "__main__":
    #test_handshake()
    test_server_scaling()
    
        
    

