#!/bin/bash

# All tests with default 80% threshold:
stack test :confcrypt-threshold-tests --coverage
# All tests with provided threshold (example with 90%):
#stack test :confcrypt-threshold-tests --coverage --ta "--threshold 90"
