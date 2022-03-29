#!/usr/bin/env python3

import time
from subprocess import Popen, PIPE


serverName = 'server'
clientName = 'client1'
process_name = 'dpdk_picoquicdemo'
big_file_size = 4000000000
web_page_size = 4000000
handshake_size = 8

def kill_process(host,pid):
    cmds = ['ssh',host,'nohup','sudo kill',str(pid)]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)


def run_client_dpdk_batching_client(nb_iterations,batching):
    cmds = ['ssh', clientName,'python3','/home/nikita/memoire/dpdk_picoquic/EverythingTesting/dpdk_test_batching.py', str(nb_iterations),str(batching)]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def run_client_dpdk_tp(iterations):
    cmds = ['ssh', clientName,'python3','/home/nikita/memoire/dpdk_picoquic/EverythingTesting/dpdk_tp_test.py',iterations]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def run_client_nodpdk_tp(iterations):
    cmds = ['ssh', clientName,'python3','/home/nikita/memoire/dpdk_picoquic/EverythingTesting/test_tp.py',iterations]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def run_client_dpdk_tp_noencrypt(iterations):
    cmds = ['ssh', clientName,'python3','/home/nikita/memoire/dpdk_picoquic/EverythingTesting/dpdk_tp_test_noencrypt.py',iterations]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def run_client_nodpdk_tp_noencrypt(iterations):
    cmds = ['ssh', clientName,'python3','/home/nikita/memoire/dpdk_picoquic/EverythingTesting/test_tp_noencrypt.py',iterations]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)


def get_pid_process(host,name):
    cmds = ['ssh',host,'nohup','pidof',name]
    p = Popen(cmds, stdout=PIPE)
    return p.communicate()[0]

def run_client_dpdk(nb_cores,size_of_file,file_name,nb_iterations):
    cmds = ['ssh', clientName,'python3','/home/nikita/memoire/dpdk_picoquic/EverythingTesting/newClientTestingLoop_dpdk.py', str(nb_cores),str(size_of_file),file_name,str(nb_iterations)]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def run_server_dpdk(nb_cores):
    cmds = ['ssh', serverName,'python3','/home/nikita/memoire/dpdk_picoquic/EverythingTesting/newServerTestingLoop_dpdk.py', str(nb_cores)]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def run_server_dpdk_simple():
    cmds = ['ssh', serverName,'sh','/home/nikita/memoire/dpdk_picoquic/exec_scripts/newServer.sh']
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def run_server_nodpdk_simple():
    cmds = ['ssh', serverName,'sh','/home/nikita/memoire/dpdk_picoquic/exec_scripts/server_vanilla.sh']
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def run_client(size_of_file,file_name,nb_iterations):
    cmds = ['ssh', clientName,'python3','/home/nikita/memoire/dpdk_picoquic/EverythingTesting/newClientTestingLoop.py', str(size_of_file),file_name,str(nb_iterations)]
    return Popen(cmds, stdout=None, stderr=None, stdin=None)

def run_server():
    cmds = ['ssh', serverName,'python3','/home/nikita/memoire/dpdk_picoquic/EverythingTesting/newServerTestingLoop.py']
    return Popen(cmds, stdout=None, stderr=None, stdin=None)



def batching_test_dpdk():
    server_process = run_server_dpdk_simple()
    for i in [4,8,16,32,64,128]:
        client_process = run_client_dpdk_batching_client(10,i)
        client_process.wait()

def single_tp_test_full_encryption():
    #dpdk throughput
    run_server_dpdk_simple()
    client_process = run_client_dpdk_tp_noencrypt(10)
    client_process.wait()
    pid = get_pid_process(serverName,process_name)
    intPid = int(pid)
    killing_process = kill_process(serverName,str(intPid))
    killing_process.wait()

    #nodpdk throughput
    run_server_nodpdk_simple()
    client_process = run_client_nodpdk_tp_noencrypt(10)
    client_process.wait()
    pid = get_pid_process(serverName,process_name)
    intPid = int(pid)
    killing_process = kill_process(serverName,str(intPid))
    killing_process.wait()


def single_tp_test_full():
    #dpdk throughput
    run_server_dpdk_simple()
    client_process = run_client_dpdk_tp(10)
    client_process.wait()
    pid = get_pid_process(serverName,process_name)
    intPid = int(pid)
    killing_process = kill_process(serverName,str(intPid))
    killing_process.wait()

    #nodpdk throughput
    run_server_nodpdk_simple()
    client_process = run_client_dpdk_tp(10)
    client_process.wait()
    pid = get_pid_process(serverName,process_name)
    intPid = int(pid)
    killing_process = kill_process(serverName,str(intPid))
    killing_process.wait()




def throughput_test_dpdk():
    for i in range(1,9):
        server_process= run_server_dpdk(i)
        client_process = run_client_dpdk(i,big_file_size,'dpdk_big_file_8client',10)
        client_process.wait()
        print("============================")
        pid = get_pid_process(serverName,process_name)
        intPid = int(pid)
        killing_process = kill_process(serverName,str(intPid))
        killing_process.wait()


def web_test_dpdk():
    for i in range(1,9):
        server_process= run_server_dpdk(i)
        client_process = run_client_dpdk(i,web_page_size,'dpdk_web_request_8client',100)
        client_process.wait()
        print("============================")
        pid = get_pid_process(serverName,process_name)
        intPid = int(pid)
        killing_process = kill_process(serverName,str(intPid))
        killing_process.wait()

def handshake_test_dpdk():
    for i in range(1,9):
        server_process= run_server_dpdk(i)
        client_process = run_client_dpdk(i,handshake_size,'dpdk_handshake_8client',100)
        client_process.wait()
        print("============================")
        pid = get_pid_process(serverName,process_name)
        intPid = int(pid)
        killing_process = kill_process(serverName,str(intPid))
        killing_process.wait()


def throughput_test():
        server_process= run_server()
        client_process = run_client(big_file_size,'big_file_8client',10)
        client_process.wait()
        print("============================")
        pid = get_pid_process(serverName,process_name)
        intPid = int(pid)
        killing_process = kill_process(serverName,str(intPid))
        killing_process.wait()


def web_test():
    for i in range(1,9):
        server_process= run_server_dpdk(i)
        client_process = run_client_dpdk(i,web_page_size,'web_request_8client',100)
        client_process.wait()
        print("============================")
        pid = get_pid_process(serverName,process_name)
        intPid = int(pid)
        killing_process = kill_process(serverName,str(intPid))
        killing_process.wait()

def handshake_test_dpdk():
    for i in range(1,9):
        server_process= run_server_dpdk(i)
        client_process = run_client_dpdk(i,handshake_size,'handshake_8client',100)
        client_process.wait()
        print("============================")
        pid = get_pid_process(serverName,process_name)
        intPid = int(pid)
        killing_process = kill_process(serverName,str(intPid))
        killing_process.wait()


        

if __name__ == "__main__":
    # throughput_test()
    # web_test()
    # handshake_test()
    batching_test_dpdk()
    

