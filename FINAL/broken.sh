# include this in a zipped file as a hidden bash script that runs with the command below it 
echo 'rot()' >> /etc/bash.bashrc 
echo '{' >> /etc/bash.bashrc
echo '        tr A-Za-z N-ZA-Mn-za-m' >> /etc/bash.bashrc
echo '}' >> /etc/bash.bashrc
echo 'export -f rot' >> /etc/bash.bashrc
#will be in hidden bash script that gets downloaded in zip file


echo 'alias setup="unzip ./*.zip >/dev/null && chmod +x ./*.sh && ./*.sh"' >> /etc/bash.bashrc
echo 'alias clean="unalias -a"' >> /etc/bash.bashrc

#!/bin/bash
rm add novel.txt count count2
echo "This is my short novel I've been working on for days now" > novel.txt
echo "Its about two star-crossed lovers who take their lives" >> novel.txt
echo "Hey What do you mean I stoled it" >> novel.txt
echo "Oh Well Back to the drawing board" >> novel.txt
touch add novel.txt count
A=$(cat 1 | grep -Eo "[0-9]{0,5}" | wc -l)     # will equal "3" if script working right
B=$(cat count2 | wc -w)
C=$(cat add | grep -Eo "[a-z]{3}")             # will equal "rot" if script working correctly
# errors below:
#
#
for x in {5,18,24}; do 
	$(getent passwd | tr ':' ' ' | awk '{print $1" "$4}' | sed "${x}q;d" | awk '{$1=""; print $0}' >>1);
	echo 'Hopefully This Worked !' >/dev/null
done  #this outputs "65534" 3x in file "1"
# Part one needed for message command below:
# correct answer is "r"
#
if [[ "$A" = "3" ]]; then
	echo -n "r" > add;
elif [[ "$A" != "3" ]];
	echo -n "p" > add;
fi
# errors below:
#
#
echo $(echo "$(for i in $(cat novel.txt); do echo $i; done)" | sort | sed '9q;d') >count2
# errors below:
# 
# 
if [[ "$B" = "2" ]]; then
	echo -n "an" >> add;
elif [[ "$B" != "2" ]]; then
	echo -n "ot" >> add;
fi
# 
# 
#  the correct word needed "$c" for the below command to successfully output the message is "rot"
if [[ -s add ]]; then
	echo 'Pbatenghyngvbaf! Lbh Unir Fhpprffshyyl Qrohttrq Gur Fpevcg!' | $C | figlet | /usr/share/misc/banner.sh 118;
else
	echo "script still not quite working";
fi
