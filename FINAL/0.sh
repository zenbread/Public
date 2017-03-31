#!/bin/bash
echo 'rot()' >> /etc/bash.bashrc
echo '{' >> /etc/bash.bashrc
echo '        tr A-Za-z N-ZA-Mn-za-m' >> /etc/bash.bashrc
echo '}' >> /etc/bash.bashrc
echo 'export -f rot' >> /etc/bash.bashrc

