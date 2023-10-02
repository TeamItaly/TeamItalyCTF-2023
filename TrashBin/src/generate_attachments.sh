#!/bin/bash

rm -rf ../attachments/*

cp -r nginx ../attachments/nginx
cp -r supervisord ../attachments/supervisord
cp -r trashbin ../attachments/trashbin
cp -r docker-compose.yml ../attachments/docker-compose.yml
cp -r Dockerfile ../attachments/Dockerfile
cp -r readflag.c ../attachments/readflag.c

cd ../attachments

echo "flag{REDACTED}" > flag.txt

rm -rf trashbin/vendor
rm -rf trashbin/src/data/*

zip -r trashbin.zip nginx supervisord trashbin docker-compose.yml Dockerfile readflag.c flag.txt
rm -rf nginx supervisord trashbin docker-compose.yml Dockerfile readflag.c flag.txt