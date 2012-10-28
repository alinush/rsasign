#!/bin/bash

function init_script() {
	orig_dir=$(readlink -f $(pwd))
	script_dir=$2
	tmp_dir=$script_dir/tmp
	logs_dir=$script_dir/logs
	logs=$logs_dir/$1-logs
	mkdir -p $tmp_dir
	mkdir -p $logs_dir
	[ -f $logs ] && rm -f $logs &>/dev/null
}

function slog() {
	local args=
	if [[ "$1" == "-n" || "$1" == "-e" ]]; then
		args="$1"
		shift
	fi
	echo $args "$@"
}

function flog() {
	slog "$@" &>>$logs
}

function log() {
	slog "$@" | tee -a $logs
}

log_fn_g=flog
function init_exec_rsasign() {
	log_fn_g=$1
}

function exec_rsasign() {
	$log_fn_g "Executing: ./rsasign $@"
	./rsasign $@ &>>$logs
}

function sign() {
	flog "Signing \"$2\" text with $3-bit key..."
	if ! ./rsasign $1 "$2" --key $script_dir/keys/rsa$3.key >$4 2>>$logs; then
		log "ERROR: Signing $1 $2 with the $3-bit key failed."
		exit 1
	fi
}

function verify() {
	flog "Verifying \"$2\" signature with $3-bit key..." &>>$logs
	if ! ./rsasign $1 "$2" --key $script_dir/keys/rsa$3.key --verify $4 &>>$logs; then
		log "ERROR: Verifying signature $4 of $1 $2 with the $3-bit key failed."
		exit 1
	fi
}

function print_welcome() {
	log
	log "$(date)"
	log "$1"
	log
	log "Temp directory: $tmp_dir"
	log "Log file: $logs"
}

function build_rsasign() {
	log "Building rsasign..."
	cd "$1"
	if ! make &>>$logs; then
	        log "ERROR: Building rsasign failed. See $logs."
        	exit 1
	fi
}

function generate_keys() {
	log "Generating keys..."
	mkdir -p "$1"
	cd $script_dir/../../scripts
	if ! ./genkeys.sh "$1" &>>$logs; then
	        log"ERROR: Generating RSA keypairs failed."
	        exit 1
	fi
}
