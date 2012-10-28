#include "hex.h"

#include "core.h"

#include <assert.h>

int hex2bin(const char * hex, int hex_len, unsigned char * bin, int bin_cap)
{
	assert(hex);
	assert(bin);
	
	size_t count = 0;
	int bin_len = hex_len % 2 ? (hex_len + 1) / 2 : hex_len / 2;
	
	if(bin_len > bin_cap) {
		err("Binary buffer capacity %d is smaller than decoded length %d.", bin_cap, bin_len);
		return -1;
	}
	
	// If we get a string such as F, we convert it to 0F, so that sscanf
	// can handle it properly.
	if (hex_len % 2) {
		char tmp[3];
		tmp[0] = '0';
		tmp[1] = hex[0];
		tmp[2] = '\0';
		
		if (sscanf(tmp, "%2hhx", bin + count) != 1)
			goto cleanup;
		
		count = 1;
		hex += 1;
	}

	for (; count < bin_len; count++) {
		if (sscanf(hex, "%2hhx", bin + count) != 1)
			goto cleanup;
		hex += 2;
	}

	return bin_len;

 cleanup:
	return -1;
}

int bin2hex(const void * bin, int bin_len, char * hex, int hex_cap)
{
	assert(bin);
	assert(hex);
	
	int hex_len = 2 * bin_len;
	
	if(hex_len > hex_cap) {
		err("Hex string buffer capacity %d is smaller than encoded length %d.", hex_cap, hex_len);
		return -1;
	}

	for (int count = 0; count < bin_len; count++)
		sprintf(hex + (count * 2), "%02x", ((unsigned char *)bin)[count]);

	return hex_len;
}

void print_hex(FILE * f, const void * bin, int bin_len, const char * before, const char * after)
{
	char hex[bin_len * 2 + 1];
	
	fprintf(f, "%s", before);
	if (bin2hex(bin, bin_len, hex, 2 * bin_len + 1) == -1)
		fprintf(f, "(Error converting to hexadecimal string)");
	else
		fprintf(f, "%s", hex);
	fprintf(f, "%s", after);
}