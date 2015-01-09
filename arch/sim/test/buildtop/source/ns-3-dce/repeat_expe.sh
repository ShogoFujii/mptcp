#! /bin/sh

slush_kb="kb/"
slush="/"
path_pre="path"

size=70

for i in `seq 1 1`; do
	path=$size$slush_kb$path_pre$path_num$slush$i
	echo ${path}
    ./waf --run "dce-iperf-mptcp_experiment -nDir=$i -s_size=$size"
    python ./pcap/file_delete2.py
done  
