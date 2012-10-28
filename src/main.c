#include "core.h"

#include <stdio.h>
#include <string.h>

#include <openssl/err.h>

#include "rsa.h"
#include "hex.h"

// We use this to store the command-line speicified program options,
// such as what text or file to encrypt, what is the encryption key, etc.
typedef struct __rs_opts_t {
	const char * text;
	const char * file;
	const char * vfy_sig;
	const char * key_file;
} rs_opts_t;

void print_usage(const char * exe_name);
int parse_arguments(int argc, char * argv[], rs_opts_t * opts);

int main(int argc, char * argv[])
{
	ERR_load_crypto_strings();

	// First, figure out what options have been specified.
	rs_opts_t opts;
	memset(&opts, 0, sizeof(opts));
	
	if(!parse_arguments(argc, argv, &opts)) {
		printf("\n");
		print_usage(argv[0]);
		return 1;
	}
		
	// Second, read the RSA key file
	RSA * keypair = rsa_keypair_read(opts.key_file);
	
	if(!keypair) {
		fprintf(stderr, "ERROR: Could not read RSA key-pair from file %s\n", opts.key_file);
		return 1;
	}
	
	// Third, allocate a buffer to hold the RSA signature
	int sig_len = RSA_size(keypair);
	unsigned char sig[sig_len];
	
	// Then, process the options.
	if(opts.vfy_sig) {
		// Convert the hexadecimal encoded signature to binary
		if(!hex2bin(opts.vfy_sig, strlen(opts.vfy_sig), sig, sig_len)) {
			fprintf(stderr, "ERROR: The provided RSA signature is not a valid hexadecimal string\n");
			return 1;
		}
		
		// Verify the signature against the provided text or file
		if(opts.text) {
			if(!rsa_sha256_verify_buf((unsigned char *)opts.text, strlen(opts.text), 
					sig, sig_len, keypair)) {
				fprintf(stderr, "ERROR: The provided RSA signature did not verify against the provided RSA keypair.\n");
				return 1;
			}
		} else if(opts.file) {
			if(!rsa_sha256_verify_file(opts.file, sig, sig_len, keypair)) {
				fprintf(stderr, "ERROR: The provided RSA signature did not verify against the provided RSA keypair.\n");
				return 1;
			}
		} else {
			err("This point should not have been reached. No --text or --file specified when verifying.");
			return 1;
		}
	} else {
		if(opts.text) {
			if(!rsa_sha256_sign_buf((unsigned char *)opts.text, strlen(opts.text), 
					sig, sig_len, keypair)) {
				fprintf(stderr, "ERROR: Could not sign the specified text.\n");
				return 1;
			} else {
				print_hex(stdout, sig, sig_len, "", "\n");
			}
		} else if(opts.file) {
			if(!rsa_sha256_sign_file(opts.file, sig, sig_len, keypair)) {
				fprintf(stderr, "ERROR: Could not sign file: %s\n", opts.file);
				return 1;
			} else {
				print_hex(stdout, sig, sig_len, "", "\n");
			}
		} else {
			err("This point should not have been reached. No --text or --file specified.");
			return 1;
		}
	}
	
	// Finally, exit.
	dbg("Exited gracefully.\n");
	return 0;
}

int parse_arguments(int argc, char * argv[], rs_opts_t * opts)
{
	if(argc == 1)
	{
		print_usage(argv[0]);
		exit(0);
	}

	for(int i = 1; i < argc; i++)
	{
		//dbg("Arg %d: %s\n", i, argv[i]);
		
		if(!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			print_usage(argv[0]);
			exit(0);
		} else if(!strcmp(argv[i], "-t") || !strcmp(argv[i], "--text")) {
			if(opts->file) {
				fprintf(stderr, "ERROR: Cannot use %s option. You have already specified the -f, --file option.\n", argv[i]);
			}
			
			if(i + 1 < argc) {
				opts->text = argv[i + 1];
				i++;
			} else {
				fprintf(stderr, "ERROR: Not enough arguments for option %s\n", argv[i]);
				return 0;
			}
		} else if(!strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")) {
			if(opts->text) {
				fprintf(stderr, "ERROR: Cannot use %s option. You have already specified the -t, --text option.\n", argv[i]);
			}
			
			if(i + 1 < argc) {
				opts->file = argv[i + 1];
				i++;
			} else {
				fprintf(stderr, "ERROR: Not enough arguments for option %s\n", argv[i]);
				return 0;
			}
		} else if(!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verify")) {
			if(i + 1 < argc) {
				opts->vfy_sig = argv[i + 1];
				i++;
			} else {
				fprintf(stderr, "ERROR: Not enough arguments for option %s\n", argv[i]);
				return 0;
			}
		} else if(!strcmp(argv[i], "-k") || !strcmp(argv[i], "--key")) {
			if(i + 1 < argc) {
				opts->key_file = argv[i + 1];
				i++;
			} else {
				fprintf(stderr, "ERROR: Not enough arguments for option %s\n", argv[i]);
				return 0;
			}
		} else {
			fprintf(stderr, "WARNING: Unknown option specified: %s\n", argv[i]);
		}
	}
	
	if(!opts->text && !opts->file) {
		fprintf(stderr, "ERROR: You must specify either a --text or a --file option.\n");
		return 0;
	}
	
	if(!opts->key_file) {
		fprintf(stderr, "ERROR: You have not specified the RSA key file using --key or -k.\n");
		return 0;
	}
	
	return 1;
}

void print_usage(const char * exe_name)
{
	printf("Usage: %s <OPTIONS> -k <KEY_FILE>\n", exe_name);
	printf("Uses the RSA public-key cryptography scheme and PKCS1 padding to digitally sign a piece of text or a file.\n");
	printf("Can also be used to verify the digital signature on something that has been previously signed using this utility.\n");
	printf("The signature of \"smth\" is computed as follows RSA_sign(\"smth\", key) = RSA_encrypt(key->priv, SHA256(\"smth\"))\n");
	
	printf("\n");
	printf("OPTIONS:\n");
	printf("    -t, --text   <text_to_sign>    signs the specified text\n");
	printf("    -f, --file   <file_to_sign>    signs the specified file\n");
	printf("    -v, --verify <rsa_sign_hex>    verifies the signature in <rsa_sign_hex>\n");
	printf("\n");
	printf("MANDATORY OPTIONS:\n");
	printf("    -k, --key    <key_file>        path to the OpenSSL-generated RSA key file\n");
	
	printf("\n");
	printf("SIGNING EXAMPLES:\n");
	printf("    %s -t \"this text will be signed\" -k rsa.key\n", exe_name);
	printf("    %s -f document.txt -k rsa.key\n", exe_name);
	printf("\n");
	printf("VERIFYING EXAMPLES:\n");
	printf("    %s -f document.txt -v 0xa19bc9503de8524356f -k rsa.key\n", exe_name);
	printf("    %s -t \"this text was signed\" -v 0xab485e847010ff3ced -k rsa.key\n", exe_name);
}