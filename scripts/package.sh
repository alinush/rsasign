#!/bin/bash

script_dir=$(readlink -f $(dirname $0))
file=${1-$script_dir/../../rsasign-$(date +%s).tar.gz}

echo "Packaging script into $file..."

trap "echo \"ERROR: Something went wrong. Exiting...\"; exit 1; " ERR

cd $script_dir/..

tar czf $file *

cd - &>/dev/null
