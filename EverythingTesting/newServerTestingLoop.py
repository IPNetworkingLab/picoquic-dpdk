import os
import sys



server_core = sys.argv[1]
#needed to make everything work
os.chdir("/home/nikita/memoire/picoquic") 
mycommand = ("sudo /home/nikita/memoire/picoquic/picoquicdemo -p 4443")
os.system(mycommand)
