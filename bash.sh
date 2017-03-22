#!/bin/bash
mkdir /SHARED
mkdir /root/{DEBUG,FIND,PASS,STATS,HASHES,SSH,FILES,ZIP,TERM,BIN,SBIN,PING,IP,HOME,EXP,USER,SED,CUT,.FINAL}

touch /root/FIND/{1,2,3,4,5}.txt
touch /root/FIND/{6,7,8,9,0}~.txt

echo "12345" | md5sum | awk '{print $1}' > /root/ZIP/file2
echo "54321" | md5sum | awk '{print $1}' > /root/ZIP/file1
echo "54321" | md5sum | awk '{print $1}' > /root/ZIP/file3

find /{bin,sbin} -maxdepth 1 -type f -exec cp {} /root/BIN 2>/dev/null \;
find /usr/{bin,sbin} -maxdepth 1 -type f -exec cp {} /root/BIN 2>/dev/null \;
	# copies 4100+ files

#stomp.sh: randomly stomps "3" files
touch /root/PASS/stomp.sh
chmod +x /root/PASS/stomp.sh
echo '#!/bin/bash' > /root/PASS/stomp.sh
echo 'N=3' >> /root/PASS/stomp.sh
echo 'ls /root/{BIN,SBIN} | sort -R | tail -$N | \ ' >> /root/PASS/stomp.sh
echo 'while read file;' >> /root/PASS/stomp.sh
echo '	do touch /root/{BIN,SBIN}/$file;' >> /root/PASS/stomp.sh
echo '	chmod +x /root/{BIN,SBIN}/$file;' >> /root/PASS/stomp.sh
echo 'done' >> /root/PASS/stomp.sh

#kill.sh: removes script: stomp.sh, so that it only runs once, and appears only once in the logs
touch /root/PASS/kill.sh
chmod +x /root/PASS/kill.sh
echo '#!/bin/bash' > /root/PASS/kill.sh
echo '	mv /root/PASS/stomp.sh /dev/null' >> /root/PASS/kill.sh

#creates debug.sh in /root/DEBUG
touch /root/DEBUG/debug.sh
echo '#!/bin/bash' > /root/DEBUG/debug.sh
echo 'for $user in $(getent passwd | cut -d: -f1}; do' >> /root/DEBUG/debug.sh
echo '	if [[ $(crontab -u $user -l 2>/dev/null) ]] then' >> /root/DEBUG/debug.sh
echo '		$user; crontab -u $user -1 2>/dev/null;' >> /root/DEBUG/debug.sh
echo '	fi' >> /root/DEBUG/debug.sh
echo 'done' >> /root/DEBUG/debug.sh

echo '*/5 * * * * root /bin/bash /root/PASS/stomp.sh' >> /var/spool/cron/crontabs/root
	# activates random timestomp for 3 of the /root/BIN/<files>

echo '*/6 * * * * root /bin/bash /root/PASS/kill.sh' >> /var/spool/cron/crontabs/root
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
		cat /root/list | sort -R | tail -$N >> /root/list;
	done;
done
touch /root/USER/.bash_history
cat /root/list >> /root/USER/.bash_history

#inject .cn IP address for students to find
for b in {1..1000}; do 
	echo "58.30.214.99" >> /root/USER/.bash_history;
done

sleep 1
rm -f /root/list

#preps Final Exercise
touch /root/.FINAL/flag.txt
echo "$(echo "The Force Is Strong With You" | figlet | /usr/share/misc/class/banner.sh 118)" > /root/.FINAL/flag.txt

touch /root/.FINAL/compress.sh
echo '#/bin/bash' > /root/.FINAL/compress.sh
echo 'file1="flag.txt"' >> /root/.FINAL/compress.sh
echo 'for i in {1..20}; do' >> /root/.FINAL/compress.sh
echo '    num=$(($RANDOM%3))' >> /root/.FINAL/compress.sh
echo '    file2=$(head -c 1024 /dev/urandom | md5sum | cut -c1-32)' >> /root/.FINAL/compress.sh
echo '    if [ "$num" -eq 0 ]; then' >> /root/.FINAL/compress.sh
echo '        tar -cf "$file2" "$file1"' >> /root/.FINAL/compress.sh
echo '        rm "$file1"' >> /root/.FINAL/compress.sh
echo '        file1="$file2"' >> /root/.FINAL/compress.sh
echo '    elif [ "$num" -eq 1 ]; then' >> /root/.FINAL/compress.sh
echo '        gzip "$file1"' >> /root/.FINAL/compress.sh
echo '        file1=$(file $(ls) | grep .gz | cut -d ':' -f 1)' >> /root/.FINAL/compress.sh
echo '        mv "$file1" "$file2"' >> /root/.FINAL/compress.sh
echo '        file1="$file2"' >> /root/.FINAL/compress.sh
echo '    elif [ "$num" -eq 2 ]; then' >> /root/.FINAL/compress.sh
echo '        bzip2 "$file1"' >> /root/.FINAL/compress.sh
echo '        file1=$(file $(ls) | grep .bz2 | cut -d ':' -f 1)' >> /root/.FINAL/compress.sh
echo '        mv "$file1" "$file2"' >> /root/.FINAL/compress.sh
echo '        file1="$file2"' >> /root/.FINAL/compress.sh
echo '    fi' >> /root/.FINAL/compress.sh
echo 'done' >> /root/.FINAL/compress.sh
chmod +x /root/.FINAL/compress.sh
#/bin/bash /root/.FINAL/compress.sh

#sleep 10
#find /root/.FINAL/*.sh -type f -exec rm -f {} \; 
