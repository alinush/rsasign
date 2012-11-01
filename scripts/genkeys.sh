#!/bin/bash

dir=${1-./}

mkdir -p $dir || exit 1

function gen_rsa_key() {
	if [ -f $dir/rsa$1.key ]; then
		echo "$1-bit key already present in $dir/rsa$1.key"
		return
	fi
	
	if ! openssl genrsa -out $dir/rsa$1.key $1 &>/dev/null; then
		echo "ERROR: Failed generating $1-bit RSA keypair."
		exit 1
	fi
}

gen_rsa_key 512
gen_rsa_key 1024
gen_rsa_key 2048
gen_rsa_key 4096

echo
echo "Great success! :)"
echo 
