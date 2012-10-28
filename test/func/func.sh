#!/bin/bash

script_dir=$(readlink -f $(dirname $0))
. $script_dir/libtests.sh

init_script "func" $script_dir
print_welcome "rsasign test suite, functional tests"
build_rsasign "$script_dir/../../src"
generate_keys "$script_dir/keys"

cd $script_dir/../../bin

log
log "Smoke tests..."
log -n " * Signing some text... "
sign "--text" "alo? ALOOO??" 4096 "$tmp_dir/bvt.sig"
verify "--text" "alo? ALOOO??" 4096 "$(cat $tmp_dir/bvt.sig)"
log "done."

log -n " * Signing a file... "
echo "hello how are we today?" >$tmp_dir/file
sign "--file" "$tmp_dir/file" 4096 "$tmp_dir/bvt.sig"
verify "--file" "$tmp_dir/file" 4096 "$(cat $tmp_dir/bvt.sig)"
log "done."


log -n " * Signing an empty file..."
touch $tmp_dir/myfile
sign "--file" $tmp_dir/myfile 4096 "$tmp_dir/bvt.sig"
verify "--file" $tmp_dir/myfile 4096 "$(cat $tmp_dir/bvt.sig)"
log "done."

trap "log; log ERROR: A test case failed. See $logs for details." ERR

# This causes the script to exit if any commands fail.
set -e

log
log "Smoke tests that SHOULD fail... "
sig=$(./rsasign --text mytext --key $script_dir/keys/rsa1024.key)
log " * Signed \"mytext\" with a 1024-bit RSA key"

log -n " * Verifying the \"mytext\" signature against \"myothertext\" with the 1024-bit key... "
! exec_rsasign --text myothertext --verify $sig --key $script_dir/keys/rsa1024.key
log "done."

log -n " * Generating a different 1024-bit RSA key... "
openssl genrsa -out $script_dir/keys/rsa1024.key 1024 &>>$logs
log "done."

log -n " * Verifying the \"mytext\" signature with an inappropriate 1024-bit key... "
! exec_rsasign --text mytext --verify $sig --key $script_dir/keys/rsa512.key
log "done."

log -n " * Verifying the \"mytext\" signature with an inappropriate 512-bit key... "
! exec_rsasign --text mytext --verify $sig --key $script_dir/keys/rsa512.key
log "done."

log -n " * Verifying an all-zeros signature... "
! exec_rsasign --text mytext --verify 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 --key $script_dir/keys/rsa512.key
log "done."

log "myfiletext lalala" >$tmp_dir/myfile
log "myfiletext tralalalala" >$tmp_dir/myotherfile
sig=$(./rsasign --file $tmp_dir/myfile --key $script_dir/keys/rsa1024.key)

if [ -z "$sig" ]; then
	log "ERROR: Could not sign \"myfile\" with a 1024-bit key"
	exit 1
fi

log " * Signed \"myfile\" with a 1024-bit RSA key."

log -n " * Verifying the \"myfile\" signature against \"myotherfile\" with the 1024-bit key... "
! exec_rsasign --file myotherfile --verify $sig --key $script_dir/keys/rsa1024.key
log "done."

log -n " * Generating a different 1024-bit RSA key... "
openssl genrsa -out $script_dir/keys/rsa1024.key 1024 &>>$logs
log "done."

log -n " * Verifying the \"myfile\" signature with an inappropriate new 1024-bit key... "
! exec_rsasign --file $tmp_dir/myfile --verify $sig --key $script_dir/keys/rsa1024.key
log "done."

log -n " * Verifying the \"myfile\" signature with an inappropriate 512-bit key... "
! exec_rsasign --file $tmp_dir/myfile --verify $sig --key $script_dir/keys/rsa512.key
log "done."

log -n " * Verifying an all-zeros signature... "
! exec_rsasign --file $tmp_dir/myfile --verify 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 --key $script_dir/keys/rsa512.key
log "done."

set +e

log
log "All is well. rsasign seems to function correctly."
log
cd $orig_dir
