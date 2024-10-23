#!/bin/sh

docker build -t enclave .
docker run -it --privileged -v `pwd`:/app/mount enclave