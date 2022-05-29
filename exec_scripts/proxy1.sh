#4e:ee:af:42:01:e5 => directlink
#52:9f:20:28:0b:c2 => proxylink

sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH ./udpsender -l 0-1 -a 0000:51:00.4 --proc-type=primary --file-prefix=rte_0 --socket-mem=2000 -- 8a:37:d5:09:9b:31

