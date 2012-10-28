#include <stdio.h>

#include "core.h"

#include "hex-test.h"

int main()
{
	int rc = 0;
	
	printf("Running hexadecimal conversion tests..\n");
	if(hex_bvt())
		printf("SUCCESS!");
	else
		printf("ERROR!");
	printf("\n");
		
	return rc;	
}