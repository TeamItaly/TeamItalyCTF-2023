#!/usr/bin/env bash

set -e

docker build -t rev03-client .
id=$(docker create rev03-client)
docker cp $id:/src/client.wasm ./assets/
docker cp $id:/src/wasm_exec.js ./assets/
docker rm -v $id