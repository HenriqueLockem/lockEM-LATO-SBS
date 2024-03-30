#!/bin/bash
# Test script to generate random and non-random data for testing 
#
# LockeEM LATO Snapshot Based Scan is a file entropy scanner to spot packed/encrypted binaries and processes on Linux and other platforms.
#
# https://www.lockem.tech
# @LockemTech

echo "Creating high entropy random executable-like file in current directory."
echo -en "\x7f\x45\x4c\x46" > ./high.entropy.test
head -c 50000 </dev/urandom >> ./high.entropy.test

echo "Creating low entropy executable-like file in current directory."
echo -en "\x7f\x45\x4c\x46" > ./low.entropy.test
head -c 50000 </dev/zero >> ./low.entropy.test

echo "Running LockEM LATO Snapshot Based Scan to generate entropy and hash values."
../sandfly-entropyscan -dir . -elf
