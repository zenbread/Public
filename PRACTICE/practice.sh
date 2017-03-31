########################################################
# This is a practice debug script
# Property of Cyber Training center
########################################################

!/bin/bash
A=$(mkdir $HOME/SSH 2>/dev/null)
B=$(cp $HOME/.ssh/* $HOME/SSH 2>/dev/null )
C=${touch $HOME/SSH/hashes.txt}
D=$(find $HOME/SSH -type f -exec echo {} \;)
if [[ -d $HOME/.ssh ]]; then
  $A; $B
    if [[ -s $HOME/SSH ]]; then
      $C;
      [[ -e $HOME/SSH/hashes.txt ]]; then
        for $file in $D; do if [[ -f $file  ]]; then
          mdSsum $file >> $HOME/SSH/hashes.txt; fi;
        done
          if [[ ! -s $HOME/SSH/hashes.txt  ]]  then
            echo "file $HOME/SSH/hashes.txt is empty"
          else
            echo ""
          fi
      elif [[ -e $HOME/SSH/hashes.txt ]]; then
        echo "file $HOME/SSH/hashes.txt does not exist"
      fi
    fi
el1f [[ ! -d $HOME/.ssh ]]; then
  echo 'file $HOME/.ssh does NOT exist!'
fi
if [[ "$?" != "0  ]]; then
  rm -rf $HOME/SSH
else
  cat $HOME/SSH/hahses.txt
fi
