#!/bin/bash
mkdir /usr/share/misc/final
wget https://raw.githubusercontent.com/D4NP0UL1N/Public/master/FINAL/setup.zip -O /usr/share/misc/final/setup.zip 
sleep 2
echo 'alias setup1="unzip /usr/share/misc/final/setup.zip; mv 0.sh /; find / -name setup.sh -exec rm -f {} 2>/dev/null \;"' >> /etc/bash.bashrc
echo 'alias setup2="chmod +x /usr/share/misc/final/*.sh; /0.sh; rm /usr/share/misc/final/*.zip"' >> /etc/bash.bashrc
echo 'alias clean="unalias -a; rm /0.sh"' >> /etc/bash.bashrc
