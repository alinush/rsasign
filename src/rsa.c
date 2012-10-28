#include "rsa.h"

#include "core.h"

#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int rsa_sha256_sign_buf(const unsigned char * data_buf, int data_length, unsigned char * sig_buf_out, int sig_buf_length, RSA * keypair)
{
	assert(data_buf);
	assert(sig_buf_out);
	assert(keypair);
	assert(sig_buf_length >= RSA_size(keypair));
	
	dbg("[%d-bit RSA] Signing %d bytes of data at %p, storing signature in %d-byte buffer at %p...\n", 
		RSA_size(keypair)*8, data_length, data_buf, sig_buf_length, sig_buf_out);
	
	int rc = 0;
	SHA256_CTX sha256;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	// Hash the data
	int status = SHA256_Init(&sha256);
	cleanup_if(status == 0,
		"SHA256_Init failed while attempting to hash the data waiting to be signed using RSA\n");

	status = SHA256_Update(&sha256, data_buf, data_length);
	cleanup_if(status == 0,
		"SHA256_Update failed while attempting to hash the data waiting to be signed using RSA\n");

	status = SHA256_Final(hash, &sha256);
	cleanup_if(status == 0,
		"SHA256_Final while attempting to hash the data waiting to be signed using RSA\n");

	// Sign the SHA256 hash of the data
	status = RSA_private_encrypt(SHA256_DIGEST_LENGTH, hash, sig_buf_out, keypair,
				RSA_PKCS1_PADDING);
				
	cleanup_if(status == -1, "Signing using RSA_private_encrypt failed. OpenSSL error: %s\n",
		ERR_error_string(ERR_get_error(), NULL));

	// Finished everything successfully!
	rc = 1;

cleanup:
	return rc;
}

int rsa_sha256_verify_buf(const unsigned char *data_buf, int data_length, const unsigned char * sig_buf, int sig_buf_length, RSA * keypair)
{
	assert(data_buf);
	assert(sig_buf);
	assert(keypair);
	assert(sig_buf_length >= RSA_size(keypair));
	
	dbg("[%d-bit RSA] Verifying %d bytes of data at %p, with signature in %d-byte buffer at %p...\n", 
		RSA_size(keypair)*8, data_length, data_buf, sig_buf_length, sig_buf);
	
	int rc = 0;
	SHA256_CTX sha256;
	
	// This is the SHA256 hash of the data that the we calculate on our own 
	unsigned char hash_calc[SHA256_DIGEST_LENGTH];
	// This is the SHA256 hash of the data that we decrypt from the provided SHA256-RSA-signature
	unsigned char hash_decrypted[SHA256_DIGEST_LENGTH];

	// Hash the data
	int status = SHA256_Init(&sha256);
	cleanup_if(status == 0,
		"SHA256_Init failed while attempting to hash the data whose RSA signature is being verified\n");

	status = SHA256_Update(&sha256, data_buf, data_length);
	cleanup_if(status == 0,
		"SHA256_Update failed while attempting to hash the data whose RSA signature is being verified\n");

	status = SHA256_Final(hash_calc, &sha256);
	cleanup_if(status == 0,
		"SHA256_Final failed while attempting to hash the data whose RSA signature is being verified\n");

	// 
	status = RSA_public_decrypt(RSA_size(keypair), sig_buf, hash_decrypted, keypair, RSA_PKCS1_PADDING);
	
	cleanup_if(status == -1, "Decrypting the SHA256 hash from the RSA signature failed. OpenSSL error: %s\n",
		ERR_error_string(ERR_get_error(), NULL));

	// Return true if the our computed SHA256 hash matches the one decrypted from the RSA signature
	return memcmp(hash_decrypted, hash_calc, SHA256_DIGEST_LENGTH) == 0;

cleanup:
	return rc;
}

int rsa_sha256_sign_file(const char * file, unsigned char * sig_buf_out, int sig_buf_length, RSA * keypair)
{
	assert(file);
	assert(sig_buf_out);
	assert(keypair);
	assert(sig_buf_length >= RSA_size(keypair));
	
	int rc = 0;
	const int buf_size = 65536;
	unsigned char buf[buf_size];
	
	// Open our file
	int fd = open(file, O_RDONLY);
	cleanup_if(fd == -1, "The open called failed on file %s\n", file);
	
	// Initialize SHA256 hashing context
	SHA256_CTX sha256;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	int status = SHA256_Init(&sha256);
	cleanup_if(status == 0,
		"SHA256_Init failed while attempting to hash the data waiting to be signed using RSA\n");
	
	// Read in the file, hashing each chunk
	ssize_t bytes_read = 0;
	while((bytes_read = read(fd, buf, buf_size)) > 0) {
		status = SHA256_Update(&sha256, buf, bytes_read);
		cleanup_if(status == 0,
			"SHA256_Update failed while attempting to hash the data waiting to be signed using RSA\n");
	}
	cleanup_if(bytes_read == -1, "The read call failed on the file %s\n", file);
	
	// Extract the SHA256 hash into our buffer
	status = SHA256_Final(hash, &sha256);
	cleanup_if(status == 0,
		"SHA256_Final while attempting to hash the data waiting to be signed using RSA\n");

	// Sign the SHA256 hash of the data
	status = RSA_private_encrypt(SHA256_DIGEST_LENGTH, hash, sig_buf_out, keypair,
				RSA_PKCS1_PADDING);
	cleanup_if(status == -1, "Signing using RSA_private_encrypt failed. OpenSSL error: %s\n",
		ERR_error_string(ERR_get_error(), NULL));
	
	// All is well.
	rc = 1;
	
cleanup:
	if(fd != -1)
		close(fd);
		
	return rc;
}

int rsa_sha256_verify_file(const char * file, const unsigned char * sig_buf, int sig_buf_length, RSA * keypair)
{
	assert(file);
	assert(sig_buf);
	assert(keypair);
	assert(sig_buf_length >= RSA_size(keypair));
	
	int rc = 0;
	const int buf_size = 65536;
	unsigned char buf[buf_size];
	
	// This is the SHA256 hash of the data that the we calculate on our own 
	unsigned char hash_calc[SHA256_DIGEST_LENGTH];
	// This is the SHA256 hash of the data that we decrypt from the provided SHA256-RSA-signature
	unsigned char hash_decrypted[SHA256_DIGEST_LENGTH];
	
	// Decrypt the SHA256 hash of the data
	int status = RSA_public_decrypt(RSA_size(keypair), sig_buf, hash_decrypted, keypair, RSA_PKCS1_PADDING);
	cleanup_if(status == -1, "Decrypting the SHA256 hash from the RSA signature failed. OpenSSL error: %s\n",
		ERR_error_string(ERR_get_error(), NULL));
	
	// Open our file
	int fd = open(file, O_RDONLY);
	cleanup_if(fd == -1, "The open called failed on file %s\n", file);
	
	// Initialize SHA256 hashing context
	SHA256_CTX sha256;
	status = SHA256_Init(&sha256);
	cleanup_if(status == 0,
		"SHA256_Init failed while attempting to hash the data waiting to be signed using RSA\n");
	
	// Read in the file, hashing each chunk
	ssize_t bytes_read = 0;
	while((bytes_read = read(fd, buf, buf_size)) > 0) {
		status = SHA256_Update(&sha256, buf, bytes_read);
		cleanup_if(status == 0,
			"SHA256_Update failed while attempting to hash the data waiting to be signed using RSA\n");
	}
	cleanup_if(bytes_read == -1, "The read call failed on the file %s\n", file);
	
	// Extract the SHA256 hash into our buffer
	status = SHA256_Final(hash_calc, &sha256);
	cleanup_if(status == 0,
		"SHA256_Final while attempting to hash the data waiting to be signed using RSA\n");
	
	// All is well.
	rc = memcmp(hash_calc, hash_decrypted, SHA256_DIGEST_LENGTH) == 0;
	
cleanup:
	if(fd != -1)
		close(fd);
	
	return rc;	
}

RSA * rsa_keypair_read(const char * file)
{
	assert(file);

	RSA * rsa = NULL;
	BIO * bio = BIO_new_file(file, "r");
	
	if(bio == NULL) {
		err("Could not open RSA key file %s", file);
		goto cleanup;
	}

	rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
	if(rsa == NULL) {
		err("PEM_read_bio_RSAPrivateKey failed reading the RSA key file %s. OpenSSL error: %s\n",
			file, ERR_error_string(ERR_get_error(), NULL));
		goto cleanup;
	}

cleanup:
	if (bio)
		BIO_free(bio);

	return rsa;
}