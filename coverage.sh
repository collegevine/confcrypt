#!/bin/bash

set -e

if ! [ -x "$(command -v hpc-threshold)" ]; then
  stack install hpc-threshold
fi

stack hpc report --all 2>&1 | hpc-threshold > hpc-threshold.log

# exit code
exit $?