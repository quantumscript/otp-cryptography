/********************************************************************
Class: CS 344 - Operating Systems
Program: Program 4 OTP (One-Time Pads) - keygen.c
Author: KC
Date: June  5 2018
Description: keygen outputs a key to stdout of length argv[1] containing only
uppercase letters and spaces and ends with \n.
**********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

int main(int argc, char* argv[]) {
	srand(time(NULL));
	int length = atoi(argv[1]);
	char key[length+1];
	memset(key, '\0', sizeof(key));
	int a;
	char character;
	for (a = 0; a < length; a++) {
		// Get only ASCII values from 65 - 90 and 32 (space)
		character = rand() % 27 + 65;
		if ( character == 91 ) character = 32; // space
		key[a] = character;
	}
	key[length] = '\0';
	printf("%s\n", key);
	return 0;
}
