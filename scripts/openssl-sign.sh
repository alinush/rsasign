#!/bin/bash

if [ $# -lt 1 ]; then
	echo "Usage $0: <file> [<key>]"
	exit 1
fi

script_dir=$(readlink -f $(dirname $0))

bin2hex() {
        hexdump -ve '1/1 "%.2x"'
	echo
}

trap "echo \"ERROR: An error occurred.\"; exit 1;" ERR

set -e

file=$1
hash=/tmp/file-$(date +%s)
key=${2-"$script_dir/../bin/keys/rsa512.key"}
cat $file | openssl dgst -binary -sha256 >$hash
openssl rsautl -in $hash -inkey $key -sign | bin2hex
rm $hash

set +e
