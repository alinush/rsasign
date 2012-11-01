#!/bin/bash

script_dir=$(readlink -f $(dirname $0))
. $script_dir/libtests.sh

init_script "openssl" $script_dir
print_welcome "rsasign test suite, OpenSSL compatibility tests"
build_rsasign "$script_dir/../../src"
generate_keys "$script_dir/keys"

trap "echo \"ERROR: A command failed.\"; exit 1;" ERR

set -e

cd $script_dir/../../scripts

echo
echo "Generating a random file..."
random_file $tmp_dir/file 1024

for size in 512 1024 2048 4096; do
	echo "Signing random file with $size-bit key..."
        ./openssl-sign.sh $tmp_dir/file $script_dir/keys/rsa$size.key >$tmp_dir/sig
	echo "Verifying signature using $size-bit key..."
	./openssl-verify.sh $tmp_dir/file $tmp_dir/sig $script_dir/keys/rsa$size.key
done

cd $orig_dir

set +e
