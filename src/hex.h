#ifndef __HEX_H_INCLUDED__
#define __HEX_H_INCLUDED__

#include <stdio.h>

int hex2bin(const char * hex, int hex_len, unsigned char * bin, int bin_cap);
int bin2hex(const void * bin, int bin_len, char * hex, int hex_cap);
void print_hex(FILE * f, const void * bin, int bin_len, const char * before, const char * after);

#endif