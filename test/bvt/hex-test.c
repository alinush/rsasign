#include "hex.h"

#include "core.h"

#include <openssl/rand.h>

#include <stdlib.h>
#include <string.h>

#define BIN_MAX_LEN 64

int hex_bvt()
{
	// RAND_bytes BVT
	const int TMP_LEN = 256;
	unsigned char tmp[TMP_LEN];
	if(!RAND_bytes(tmp, TMP_LEN)) {
		err("RAND_bytes failed generating random data.");
		return 0;
	}
	
	for(int i = 0; i < 128; i++) {
		// Get a random seed
		unsigned int seed;
		RAND_bytes((unsigned char *)&seed, sizeof(seed));
	
		// Get a random length for the binary data
		srand(seed);
		int bin_len = rand() % BIN_MAX_LEN + 1;
	
		// Get random data
		unsigned char bin[bin_len];
		RAND_bytes(bin, bin_len);
		print_hex(stdout, bin, bin_len, "bin: ", "\n");
	
		// Convert to hexadecimal
		int hex_len = 2 * bin_len;
		char hex[hex_len + 1];
		if(!bin2hex(bin, bin_len, hex, hex_len)) {
			err("Binary to hexadecimal conversion failed.");
			return 0;
		}
		printf("bin2hex(bin): %s\n", hex);
	
		// Convert back to binary
		unsigned char bin2[bin_len];
		if(!hex2bin(hex, hex_len, bin2, bin_len)) {
			err("Hexadecimal to binary conversion failed.");
			return 0;
		}
		print_hex(stdout, bin2, bin_len, "hex2bin(bin2hex(bin)): ", "\n");
	
		// Compare bin with hex2bin(bin2hex(bin)
		if(memcmp(bin, bin2, bin_len)) {
			err("Decoding hexadecimal string back to binary produced a different result: hex2bin(bin2hex(bin)) != bin");
			return 0;
		}
	}
	
	return 1;
}
