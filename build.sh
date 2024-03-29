#!/bin/bash
# Build script for LockEM SBS
#
# LockEM SBS is an entropy scanner to spot packed/encrypted binaries and processes on Linux and Windows PE files.
#
# MIT Licensed (c) 2024 LockEM
# https://www.lockem.tech
# @LockemTech

echo "Building for current OS."
go build -ldflags="-s -w"
