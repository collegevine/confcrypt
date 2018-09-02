#!/bin/bash

set -e

stack exec hlint -- . --hint=.hlint.yaml

