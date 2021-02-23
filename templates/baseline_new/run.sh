#!/bin/bash
#
# Script to get Aarno's exploit for CVE-2008-1699 ready
# for testing.
#
# We use docker to host the vulnerable PHP code.

if [ -z $DATA_DIR] ; then
    DATA_DIR=`pwd`/data
fi

# Call when you want to print a message and exit the script
exit_on_error() {
    echo $1
    exit 1
}

install_stuff()
{
    export DEBIAN_FRONTEND=noninteractive
    apt update ||
    apt -y install docker.io
}

#install_stuff || exit_on_error "Couldn't install things"

cd $DATA_DIR && ./doit.sh
