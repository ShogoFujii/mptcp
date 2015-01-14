#! /bin/sh

slush_kb="kb/"
slush="/"
path_pre="path"

node_num=3
rtrs_num=4
size=`expr 1024 \/ $node_num`

for i in `seq 1 1`; do
	path=$size$slush_kb$path_pre$path_num$slush$i
	echo ${path}
    ./waf --run "dce-iperf-mptcp_incast -nDir=$i -s_size=$size -nNodes=$node_num -nRtrs=$rtrs_num"
    python ./pcap/file_delete2.py
done  
