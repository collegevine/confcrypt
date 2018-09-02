#!/bin/bash

set -e

OS=linux
HLINT_VERSION=2.1.8
HLINT_RELEASE=v$HLINT_VERSION/hlint-$HLINT_VERSION-x86_64-$OS.tar.gz
HLINT_URL=https://github.com/ndmitchell/hlint/releases/download/$HLINT_RELEASE
TEMP=$(mktemp -d .hlint-XXXXX)
HLINT=$TEMP/hlint-$HLINT_VERSION/hlint

echo Downloading hlint-$HLINT_VERSION...
curl --progress-bar --location --output "$TEMP"/hlint.tar.gz "$HLINT_URL"
tar -xzf "$TEMP"/hlint.tar.gz -C "$TEMP"

hlint .

