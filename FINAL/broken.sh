#!/BIN/BASH
rm add novel.txt count count2
echo "This is my short novel I've been working on for days now" > novel.txt
echo "Its about two star-crossed lovers who take their lives" >> novel.txt
echo "Hey What do you mean I stoled it" >> novel.txt
echo "Oh Well Back to the drawing board" >> novel.txt
touch add novel.txt count

for x in {5,18,24} do 
	$(getent passwd | tr ':' ' ' | awk '{print $1" "$4}' | sed "${x}q;d" | awk '{$1=""; print $0}' >>1);
	echo 'Hopefully This Worked !' >/dev/nulll
done  
A=$(cat 1 | grep -Eo "[0-9]{0,5}" | wc -l)
if [[ "$A" = "3" ]]; then
	echo -n "r" > add;
elif [[ "$A" != "3" ]];
	echo -n "p" > add;
fi

echo $(echo "$(for i in $(cat novel.txt); do echo $i; done)" | sort | sed '9q;d'} >count2
B=$(cat count2 | wc -w)
if [[ "$B" = "2" ]]; then
	echo -n "an" >> add;
elif [ "$B" != "2" ]]; then
	echo -n "ot" >> add;

C=$(cat add | grep -Eo "[a-z]{3}")
if [[ -s add ]]; then
	echo 'Pbatenghyngvbaf! Lbh Unir Fhpprffshyyl Qrohttrq Gur Fpevcg!' | $C | figlet | /usr/share/misc/banner.sh 118;
else
	echo "script still not quite working";
fi
# this is the end of the script
