#ifndef __RSA_H_INCLUDED__
#define __RSA_H_INCLUDED__

#include <openssl/rsa.h>

int rsa_sha256_sign_buf(const unsigned char * data_buf, int data_length, unsigned char * sig_buf_out, int sig_buf_length, RSA * keypair);
int rsa_sha256_verify_buf(const unsigned char *data_buf, int data_length, const unsigned char * sig_buf, int sig_buf_length, RSA * keypair);

int rsa_sha256_sign_file(const char * file, unsigned char * sig_buf_out, int sig_buf_length, RSA * keypair);
int rsa_sha256_verify_file(const char * file, const unsigned char * sig_buf, int sig_buf_length, RSA * keypair);

RSA * rsa_keypair_read(const char * file);

#endif