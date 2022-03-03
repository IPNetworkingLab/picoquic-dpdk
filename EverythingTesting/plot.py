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

def get_data(file,index):
    file1 = open(file, 'r')
    ret = []
    while True:
        line = file1.readline()
        if not line:
            break
        tab = line.split(" ")
        ret.append(float(tab[index]))
    return ret
    
def plot_big_file():
    throughput = []
    nb_cores = [i for i in range(1,9)]
    for i in range(1,9):
        throughput.append(take_average("output_big_file_8client_{}.txt".format(i),throughput_index)*8)
    plt.ylabel('throughput (Mbps)')
    plt.plot(nb_cores, throughput)
    plt.savefig('big_file.png')
    plt.clf()

    
        

def plot_web_request():
    times = []
    nb_cores = [i for i in range(1,9)]
    for i in range(1,9):
        times.append(get_data("output_web_request_8client_{}.txt".format(i),time_index))
    print(len(times))
    print(len(nb_cores))
    plt.boxplot(times, vert=True, patch_artist=True, labels=nb_cores,showfliers=False)
    plt.ylabel('time(s)') 
    plt.xlabel('# server cores')
    plt.title('response time for a 4MB file')
    plt.savefig('web_request.png')
    plt.clf()


def plot_handshake():
    times = []
    nb_cores = [i for i in range(1,9)]
    for i in range(1,9):
        times.append(get_data("output_handshake_8client_{}.txt".format(i),time_index))

    plt.boxplot(times, vert=True, patch_artist=True, labels=nb_cores,showfliers=False) 
    plt.ylabel('time(s)') 
    plt.xlabel('# server cores')
    plt.title('response time for a 8bytes file')
    plt.savefig('handshake.png')
    plt.clf()


if __name__ == "__main__":
    plot_big_file()
    plot_web_request()
    plot_handshake()


