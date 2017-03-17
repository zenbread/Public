#!/bin/bash
mkdir /SHARED
mkdir $HOME/{FIND,PASS,STATS,HASHES,SSH,FILES,ZIP,TERM,BIN,SBIN,SSH,PING,IP,HOME,EXP,USER,SED,CUT}

touch $HOME/FIND/{1,2,3,4,5}.txt
touch $HOME/FIND/{6,7,8,9,0}~.txt
	
echo "12345" | md5sum | awk '{print $1}' > $HOME/ZIP/file2
echo "54321" | md5sum | awk '{print $1}' > $HOME/ZIP/file1
echo "54321" | md5sum | awk '{print $1}' > $HOME/ZIP/file3

find /{bin,sbin} -maxdepth 1 -type f -exec cp {} $HOME/BIN 2>/dev/null \;
find /usr/{bin,sbin} -maxdepth 1 -type f -exec cp {} $HOME/BIN 2>/dev/null \;
	# copies 4100+ files

#stomp.sh: randomly stomps "3" files
mkdir /root/PASS
touch /root/PASS/stomp.sh
chmod +x /root/PASS/stomp.sh
echo '#!/bin/bash' > /root/PASS/stomp.sh
echo 'N=3' >> /root/PASS/stomp.sh
echo 'ls $HOME/{BIN,SBIN} | sort -R | tail -$N | \ ' >> /root/PASS/stomp.sh
echo 'while read file;' >> /root/PASS/stomp.sh
echo '	do touch $HOME/{BIN,SBIN}/$file;' >> /root/PASS/stomp.sh
echo '	chmod +x $HOME/{BIN,SBIN}/$file;' >> /root/PASS/stomp.sh
echo 'done' >> /root/PASS/stomp.sh

#kill.sh: removes script: stomp.sh, so that it only runs once, and appears only once in the logs
touch /root/PASS/kill.sh
chmod +x /root/PASS/kill.sh    
echo '#!/bin/bash' > /root/PASS/kill.sh
echo 'rm -f $HOME/PASS/stomp.sh' >> /root/PASS/kill.sh

echo '*/3 * * * * root /bin/bash /root/PASS/stomp.sh' >> /var/spool/cron/crontabs/root
	# activates random timestomp for 3 of the $HOME/BIN/<files>
	
echo '*/4 * * * * root /bin/bash /root/PASS/kill.sh' >> /var/spool/cron/crontabs/root
	# deletes timestomp script: stomp.sh, so it only runs ONCE
	
for x in {LARRY,CURLY,MOE}; do
	useradd -M $x;
	echo "$x:password" | chpasswd;
done
# generates IP addresses for activity: IPs in bash_history
touch /root/list
for a in {1..3}; do
	for y in {1..3}; do
		for x in {1..100}; do
			dd if=/dev/urandom bs=4 count=1 2>/dev/null \
			| od -An -tu1 | sed -e 's/^ *//' -e 's/  */./g' >> /root/list;
		done;
	done
	N=100
	for z in {1..10}; do
		cat list | sort -R | tail -$N >> /root/list;
	done;
done
touch $HOME/USER/.bash_history
cat /root/list >> $HOME/USER/.bash_history
#inject .cn IP address for students to find
for b in {1..1000}; do 
	echo "58.30.214.99" >> $HOME/USER/.bash_history;
done
sleep 1
rm -f /root/list
