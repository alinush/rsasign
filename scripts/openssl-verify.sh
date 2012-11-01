#!/bin/bash

if [ $# -lt 2 ]; then
	echo "Usage $0: <file> <hex-rsa-signature> [<key>]"
	exit 1
fi

script_dir=$(readlink -f $(dirname $0))

bin2hex() {
        hexdump -ve '1/1 "%.2x"'
	echo
}

hex2bin() {
#    echo -n $1 | sed 's/\([0-9a-f]\{2\}\)/\\\\\\x\1/gI'	
	echo -n "$1" | sed 's/\([0-9A-F]\{2\}\)/\\\\\\x\1/gI' | xargs printf
}

set -e

sig=/tmp/sig-$(date +%s)
hash=/tmp/hash-$(date +%s)
dec_hash=/tmp/dec_hash-$(date +%s)
file=$1
sig_hex=$(cat $2)
key=${3-"$script_dir/../bin/keys/rsa512.key"}

cat $file | openssl dgst -binary -sha256 >$hash
hex2bin $sig_hex >$sig
openssl rsautl -verify -in $sig -inkey $key >$dec_hash

set +e

cmp $hash $dec_hash &>/dev/null
rc=$?

rm $hash $sig $dec_hash

exit $rc
