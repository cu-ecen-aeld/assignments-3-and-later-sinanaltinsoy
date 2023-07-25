#!/bin/sh

#Assignment-1

if [ $# -lt 2 ]
then
	echo "Missing input arguments! Hint: finder.sh <path> <str> "
    exit 1
else
	SEARCHSTR=$2
	FILEDIR=$1
fi

if [ ! -d "$FILEDIR" ]
then
    echo "$FILEDIR directory is not exist!"
    exit 1
fi

X=$(find $FILEDIR -type f | wc -l)
Y=$(grep -r $SEARCHSTR $FILEDIR | wc -l)

echo "The number of files are $X and the number of matching lines are $Y"
exit 0