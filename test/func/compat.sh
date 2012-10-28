#!/bin/bash

script_dir=$(readlink -f $(dirname $0))
. $script_dir/libtests.sh

init_script "func" $script_dir
print_welcome "rsasign test suite, OpenSSL compatibility tests"
build_rsasign "$script_dir/../../src"
generate_keys "$script_dir/keys"

cd $script_dir/../../bin

cd $orig_dir
