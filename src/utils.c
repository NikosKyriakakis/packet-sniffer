#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void fatal(const char *origin, const char *error_buffer)
{
	fprintf(stderr, "Fatal error in %s: %s\n", origin, error_buffer);
	exit(EXIT_FAILURE);
}

void raw_dump(const unsigned char *buffer, const unsigned int size) 
{
	unsigned int mod_i;
	
	for(unsigned int i = 0; i < size; i++) {
		printf("%02x ", buffer[i]); 
		mod_i = i % 16;
		if ((mod_i == 15) || (i == size - 1)) {
			for(unsigned int j = 0; j < 15 - mod_i; j++)
				printf(" ");
			printf("| ");
			for(unsigned int j = (i - mod_i); j <= i; j++) {
				if ((buffer[j] > 31) && (buffer[j] < 127))
					printf("%c", buffer[j]);
				else
					printf(".");
			}
			printf("\n");
		}
	}
}
