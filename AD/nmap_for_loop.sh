#!/bin/bash

if [ $# -lt 1 ] ; then
	echo " usage: $0 <nmap_results>"
	exit 1
fi
# this first CMD extracts only the protocols used in the nmap_results; outputs to 'A'
cat $1 |grep open|grep -v "OSScan"|sort|cut -d"/" -f2|column -t|cut -d" " -f5|sort|uniq > A

# this CMD removes all the grabage text we don't need from the nmap_results; outputs to 'B'
cat $1 | grep -v "exact\|MAC\|OS\|hop\|Running\|Device\|fingerprint\|shown\| \
latency\|Warning\|done\|LABS\|org" > B

sleep 1
# this CMD adds 20 blank lines (;p) in front of the regex 'report' of the nmap_results, preventing CMD bleed: -B20; directly edits 'B'
sed '/report/{x;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;p;x}' -i B 2>/dev/null

byline=$(cat A)
# this for loop ouputs each protocol, followed by a line, and the applicable hosts with the protocol open; outputs to 'C'
for protocol in $byline ; do
	echo
	echo $protocol
	echo "================"
	cat B | grep -B20 $protocol > C
	grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' C
	# greps for IP addresses up to 20 lines above 'open protocol' recursively
done
#RESET
cp nmap.orig.txt NMAP_all_hosts.txt
