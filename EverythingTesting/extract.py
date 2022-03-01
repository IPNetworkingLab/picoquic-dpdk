
file1 = open('output.txt', 'r')

throughput = 0
counter = 0
while True:
    # Get next line from file
    line = file1.readline()
    if not line:
        break
    tab = line.split(" ")
    throughput += float(tab[6])
    counter +=1
print(throughput/counter)
    