#!/bin/bash

script_dir=$(readlink -f $(dirname $0))
. $script_dir/libtests.sh

init_script "fuzzy" $script_dir
print_welcome "rsasign test suite, fuzzy functional tests"
build_rsasign "$script_dir/../../src"
generate_keys "$script_dir/keys"

cd $script_dir/../../bin

num_iter=${1-8}
text_size=64
log "Signing random data..."
log -n " * Signing text ($num_iter samples)... "
for ((i=0; i<$num_iter; i++)); do
	text=$(random_text $text_size)
	for key_size in 512 1024 2048 4096; do
		sign "--text" "$text" $key_size "$tmp_dir/fuzzy.sig"
		verify "--text" "$text" $key_size "$(cat $tmp_dir/fuzzy.sig)"
	done
done
log "done."

log -n " * Signing files ($num_iter samples)... "
file_size=1024
for ((i=0; i<$num_iter; i++)); do
	text=$(random_file $tmp_dir/file $file_size)
	for key_size in 512 1024 2048 4096; do
		sign "--file" "$tmp_dir/file" $key_size "$tmp_dir/fuzzy.sig"
		verify "--file" "$tmp_dir/file" $key_size "$(cat $tmp_dir/fuzzy.sig)"
	done
done
log "done."

log
log "All is well. Signed random data and verified signatures successfully."
log
cd $orig_dir
