#!/bin/bash

# Build the Linux docker image, spin up a container, then copy out the confcrypt binary and
# dump it locally. Finally, tear down the image.

docker build -t confcrypt-linux -f build/Ubuntu-18.04.Dockerfile .
id=$(docker create confcrypt-linux)
docker cp "$id":/root/.local/bin/confcrypt confcrypt
docker rm "$id"
tar -czf confcrypt-linux-x64.tar.gz confcrypt
