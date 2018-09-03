#!/bin/bash

set -e

stack install hlint
stack exec hlint -- . --hint=.hlint.yaml

