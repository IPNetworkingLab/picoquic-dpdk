#!/bin/bash
sudo ./dpdk_picoquicdemo -l 0-4 -a 0000:51:00.0 -- -q qlogs -p 4443 -1
