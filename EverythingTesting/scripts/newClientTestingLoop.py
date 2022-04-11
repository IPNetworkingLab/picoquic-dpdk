import os
import sys



os.chdir("/home/nikita/memoire/picoquic/")
size_of_file = sys.argv[1]
file_name = sys.argv[2]
nb_of_iteration = int(sys.argv[3])

mycommand = ("sudo /home/nikita/memoire/picoquic/picoquicdemo -N {} -D localhost 4443 /{}"
            "| grep Mbps >> EverythingTesting/output_{}.txt")

os.system(mycommand.format(nb_of_iteration,size_of_file,file_name))
