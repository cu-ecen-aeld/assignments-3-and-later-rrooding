#!/bin/bash

WRITEFILE=$1;
WRITESTR=$2;

if [ -z "$WRITEFILE" ] || [ -z "$WRITESTR" ]; then
    echo "writer.sh expects 2 arguments: ./writer.sh <writefile> <writestr>";
    exit 1;
fi;

DIRNAME=`dirname $WRITEFILE`

if [ ! -d $DIRNAME ]; then
    mkdir -p $DIRNAME;
fi;

echo $WRITESTR > $WRITEFILE;