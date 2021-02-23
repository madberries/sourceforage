#!/bin/bash

# Call when you want to print a message and exit the script
exit_on_error() {
    echo $1
    exit 1
}

docker build -t aarno-cve-2006-0313 . || exit_on_error "Couldn't build docker container"
docker run --rm --privileged -p 80:80 aarno-cve-2006-0313

