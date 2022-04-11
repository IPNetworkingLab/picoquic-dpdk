import matplotlib.pyplot as plt
 

def plot_graph(serverCores):
    
    x = [i for i in range(1,9)]
    y = [cal_average(i),for i in range(1,9)]
    plt.plot(x, y)
    plt.xlabel('x - axis')
    plt.ylabel('y - axis')
    plt.title('My first graph!')    
    plt.show()

def cal_average(serverCores):
    f = open('output_8client_{}servercore.txt'.format(servercore), 'r')
    throughput = 0
    counter = 0
    while True:
        # Get next line from file
        line = f.readline()
        if not line:
            break
        tab = line.split(" ")
        throughput += float(tab[6])
        counter +=1
    return throughput/counter
