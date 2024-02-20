// checkcChars() function to check for bad characters in plaintext and key

#include "functions.h"

void checkChars(char array[], int bytes, char* fileName) {
	int a;
	for (a=0; a < bytes; a++) {
		if (array[a] > 90 || (array[a] < 65 && array[a] != 32)) {
			fprintf(stderr, "Error: bad character(s) found in %s!\n", fileName);
			exit(1);
		}
	}
	return;
}
