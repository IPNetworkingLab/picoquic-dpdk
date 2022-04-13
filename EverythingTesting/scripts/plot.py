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

def comparison_aes_chacha():
    van_chacha = get_data("../data/output_nodpdk_chacha.txt",6)
    dpdk_chacha = get_data("../data/output_dpdk_chacha.txt",6)
    van_aes = get_data("../data/output_nodpdk_tp_enc.txt",6)
    dpdk_aes = get_data("../data/output_dpdk_tp_enc.txt",6)


    data = [van_chacha,dpdk_chacha,van_aes,dpdk_aes]
    fig, ax = plt.subplots()
    columns = data
    ax.boxplot(columns)
    plt.title("TP comparison")
    plt.xticks([1,2,3,4], ["pquic_chacha","dpdk_chacha","pquic_aes","dpdk_aes"])
    plt.ylabel("throughput(mbps)")  
    # show plot
    plt.savefig("../plots/aes_chacha.png")
    

def tp_comparison_encryption():
    van_pquic = get_data("../data/output_nodpdk_tp_enc.txt",6)
    dpdk_pquic = get_data("../data/old/output_tp_dpdk.txt",6)
    van_pquic_noencrypt = get_data("../data/output_nodpdk_tp.txt",6)
    dpdk_pquic_noencrypt = get_data("../data/output_dpdk_tp.txt",6)


    data = [van_pquic,dpdk_pquic,van_pquic_noencrypt,dpdk_pquic_noencrypt]
    fig, ax = plt.subplots()
    columns = data
    ax.boxplot(columns)
    plt.title("TP comparison")
    plt.xticks([1,2,3,4], ["pquic_e","dpdk_pquic_e","pquic_noe","dpdk_pquic_noe"])
    plt.ylabel("throughput(mbps)")  
    # show plot
    plt.savefig("tp_encryptionNew.png")

def tp_comparison():
    van_pquic = get_data("output_tp_van.txt",6)
    dpdk_pquic = get_data("output_tp_dpdk.txt",6)

    mean_van_pquic = sum(van_pquic)/len(van_pquic)
    mean_dpdk_pquic = sum(dpdk_pquic)/len(dpdk_pquic)
    plt.title("throughput comparison")
    plt.ylabel("throughput (mbps)")
    data = [mean_van_pquic,mean_dpdk_pquic]
    names = ["pquic","dpdk-pquic"]

    plt.bar(names,data)
    plt.savefig("tp_comp.png")

def copy_comparison():
    copy = get_data("../data/output_copyv2.txt",6)
    nopy = get_data("../data/output_nopyv2.txt",6)
    data = [copy,nopy]
    
    fig, ax = plt.subplots()
    columns = data
    ax.boxplot(columns)
    plt.title("TP comparison")
    plt.xticks([1,2], ["copy","nocopy"])
    plt.ylabel("throughput(mbps)")  
    # show plot
    plt.savefig("../plots/copy_nocopyv2.png")

def handshake_comparison():

    van_pquic = get_data("output_handshakes_van_clean.txt",5)
    dpdk_pquic = get_data("output_handshakes_dpdk_clean.txt",5)
    data = [[e/20 for e in van_pquic],[e/20 for e in dpdk_pquic]]
    fig, ax = plt.subplots()
    columns = data
    ax.boxplot(columns)
    plt.title("handshake comparison")
    plt.xticks([1, 2], ["pquic","dpdk_pquic"])
    plt.ylabel("hps(hz)")  
    # show plot
    plt.savefig("handshake_comp.png")

def batching_comparison():
    data = []
    for i in [4, 8, 16, 32]:
        data.append(get_data("output_tp_dpdk_{}.txt".format(i),6))
    fig, ax = plt.subplots()
    columns = data
    ax.boxplot(columns)
    plt.title("analysis of batching")
    plt.xticks([1, 2, 3, 4], [4, 8,16,32])
    plt.xlabel("batche size (packet)")
    plt.ylabel("throughput (mbps)")
    plt.show()
    # plt.savefig("batching.png")

def batching_comparison_8client():
    data = []
    for i in [4, 32]:
        data.append(get_data("output_tp_dpdk_8_{}.txt".format(i),6))
    fig, ax = plt.subplots()
    columns = data
    ax.boxplot(columns)
    plt.title("analysis of batching")
    plt.xticks([1, 2], [4, 32])
    plt.xlabel("batche size (packet)")
    plt.ylabel("throughput (mbps)")
    plt.savefig("batching_8.png")
  

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
    # plot_big_file()
    # plot_web_request()
    # plot_handshake()
    # tp_comparison()
    #batching_comparison_8client()
    # tp_comparison_encryption()
    # comparison_aes_chacha()
    copy_comparison()
    #handshake_comparison()
    #batching_comparison()


