sudo echo 6 | sudo tee /sys/bus/pci/devices/0000:8a:00.1/sriov_numvfs ;\
sudo ifconfig ens1f1v1 10.10.0.2 netmask 255.255.255.0 ;\
sudo ifconfig ens1f1v2 10.10.0.3 netmask 255.255.255.0 ;\
sudo ifconfig ens1f1v3 10.10.0.4 netmask 255.255.255.0 ;\
sudo ifconfig ens1f1v4 10.10.0.5 netmask 255.255.255.0 ;\
sudo ip netns add nsCLIENT ;\
sudo ip netns add nsSERVER ;\
sudo ip link set ens1f1v0 netns nsCLIENT ;\
sudo ip link set ens1f1v5 netns nsSERVER ;\
sudo ip netns exec nsCLIENT sudo ifconfig ens1f1v0 10.10.0.1 netmask 255.255.255.0 ;\
sudo ip netns exec nsSERVER sudo ifconfig ens1f1v5 10.10.0.6 netmask 255.255.255.0 ;\
sudo ip netns exec nsCLIENT sudo arp -s 10.10.0.6 2e:fd:f4:32:df:8d ;\
sudo ip netns exec nsSERVER sudo arp -s 10.10.0.1 2a:a5:a3:93:f5:f2
