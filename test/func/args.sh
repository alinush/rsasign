#!/bin/bash

script_dir=$(readlink -f $(dirname $0))
. $script_dir/libtests.sh

init_script "args" $script_dir
print_welcome "rsasign test suite, command line arguments tests"
build_rsasign "$script_dir/../../src"
generate_keys "$script_dir/keys"

cd $script_dir/../../bin

trap "log \"ERROR: An rsasign command failed\"; exit 1" ERR

# This causes the script to exit if any commands fail.
#set -e

init_exec_rsasign log
log
log "Executing rsasign commands that should succeed..."
exec_rsasign
exec_rsasign --help
exec_rsasign -h
exec_rsasign -t "alinaremeresisejoacapeafaracubobi" -k $script_dir/keys/rsa512.key
echo "apoteoza dezuavarii persusasive, conform marelui nita cristian daniel" >$tmp_dir/myfile
exec_rsasign -f $tmp_dir/myfile -k $script_dir/keys/rsa512.key


log
log "Executing rsasign commands that should fail..."
! exec_rsasign --text mytexthere

id=$(openssl rand -hex 32)
! exec_rsasign --text mytexthere --key bad-key-file-$id

! exec_rsasign --text mytexthere --verify 00bad00bad00bad00 --key $script_dir/keys/rsa512.key

! exec_rsasign --text mytexthere --key $0

rm $tmp_dir/myfile
touch $tmp_dir/myfile
! exec_rsasign --file myfile

#set +e

log
log "All is well. Command-line arguments seem to function correctly."
log
cd $orig_dir
