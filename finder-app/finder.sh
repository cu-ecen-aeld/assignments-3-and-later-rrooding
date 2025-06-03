#!/bin/bash

FILESDIR=$1;
SEARCHSTR=$2;

if [ -z "$FILESDIR" ] || [ -z "$SEARCHSTR" ]; then
    echo "finder.sh expects 2 arguments: ./finder.sh <filesdir> <searchstr>";
    exit 1;
fi;

if [ ! -d "$FILESDIR" ]; then
    echo "Directory $FILESDIR does not exist";
    exit 1;
fi;

NUMFILES=$(find "$FILESDIR" -type f | wc -l)
NUMLINES=$(grep -r "$SEARCHSTR" "$FILESDIR" 2>/dev/null | wc -l)

echo "The number of files are $NUMFILES and the number of matching lines are $NUMLINES";