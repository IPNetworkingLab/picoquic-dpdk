import matplotlib.pyplot as plt

throughput_index = 6
time_index = 4

def take_average(file,index):
    file1 = open(file, 'r')
    throughput = 0
    counter = 0
    while True:
        line = file1.readline()
        if not line:
            break
        tab = line.split(" ")
        throughput += float(tab[index])
        counter +=1
    return(throughput/counter)
    
def plot_big_file():
    throughputs = []
    nb_cores = [i for i in range(1,9)]
    for i in range(1,):
        throughput.append(take_average("output_big_file_8client_{}.txt".format(i),throughput)*8,throughput_index)
    plt.ylabel('throughput (Mbps)')
    plt.ylabel('throughput (Mbps)')
    plt.plot(nb_cores, throughput)
    plt.savefig('big_file.png')

    
        

def plot_web_request():
    times = []
    nb_cores = [i for i in range(1,9)]
    for i in range(1,):
        throughput.append(take_average("web_request_8client_{}.txt".format(i),throughput),time_index)
    plt.ylabel('throughput (Mbps)')
    plt.ylabel('throughput (Mbps)')
    plt.plot(nb_cores, times)
    plt.savefig('web_request.png')


def plot_handshake():
    times = []
    nb_cores = [i for i in range(1,9)]
    for i in range(1,):
        throughput.append(take_average("handshake_8client_{}.txt".format(i),throughput),time_index)
    plt.ylabel('throughput (Mbps)')
    plt.ylabel('throughput (Mbps)')
    plt.plot(nb_cores, times)
    plt.savefig('handshake.png')




fig = plt.figure()

versions = ['localhost_picoquic', 'picoquic', 'dpdk_picoquic']
throughput = [4396,931,9391]

plt.bar(versions, throughput)

plt.ylabel('throughput (Mbps)')
plt.savefig('graph.png')

