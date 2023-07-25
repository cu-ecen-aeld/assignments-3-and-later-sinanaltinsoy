#!/bin/sh

#Assignment-1

if [ $# -lt 2 ]
then
	echo "Missing input arguments! Hint: writer.sh <file> <str> "
    exit 1
else
	WRITESTR=$2
	WRITEFILE=$1
fi

install -D /dev/null $WRITEFILE
echo $WRITESTR >> $WRITEFILE

exit 0