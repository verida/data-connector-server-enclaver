#!/bin/sh

docker rm $(docker ps -aq)
docker container prune
docker volume prune