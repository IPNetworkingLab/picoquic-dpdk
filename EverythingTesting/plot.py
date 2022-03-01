import matplotlib.pyplot as plt

fig = plt.figure()
versions = ['localhost_picoquic', 'picoquic', 'dpdk_picoquic']
throughput = [4396,931,9391]

plt.bar(versions, throughput)

plt.ylabel('throughput (Mbps)')
plt.savefig('graph.png')

