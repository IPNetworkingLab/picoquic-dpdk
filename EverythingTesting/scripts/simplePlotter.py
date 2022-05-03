import matplotlib.pyplot as plt

throughput_index = 6
time_index = 4

class ItemToPlot:
    def __init__(self, label,getDataFunction,args):
        self.label = label
        self.getDataFunction = getDataFunction
        self.args = args
        
    def getData(self):
        return self.getDataFunction(*self.args)
        
        
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

def compararison_plot(item1,item2,title,yLabel,outputFileName):
    data1 = item1.getData()
    data2 = item2.getData()
    plt.title(title)
    plt.ylabel(yLabel)
    data = [data1,data2]
    names = [item1.label,item2.label]
    plt.bar(names,data)
    plt.savefig(outputFileName)
    


if __name__ == "__main__":
    
    
    item1 = ItemToPlot("nodpdk",take_average,("../data/output_nodpdk_tp_enc.txt",throughput_index))
    item2 = ItemToPlot("dpdk",take_average,("../data/output_dpdk_tp_enc.txt",throughput_index))
    
    compararison_plot(item1,item2,"Throughput comparison","Throughput(Mbps)","../plots/ThroughputComparison.png")
   

