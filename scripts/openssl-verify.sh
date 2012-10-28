#!/bin/bash

if [ $# -ne 2 ]; then
	echo "Usage $0: <file> <hex-rsa-signature> [<key>]"
	exit 1
fi

script_dir=$(readlink -f $(dirname $0))

bin2hex() {
        hexdump -ve '1/1 "%.2x"'
	echo
}

hex2bin() {
	
}

file=$1
key=${2-"$script_dir/../bin/keys/rsa512.key"}
cat $file | openssl dgst -binary -sha256 >hash
openssl rsautl -in hash -inkey $key -sign | bin2hex
rm hash
