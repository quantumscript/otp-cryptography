// Functions.h

#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <stdio.h>
#include <stdlib.h>

// Error function
void error(const char *msg) { perror(msg); exit(1); }

// Check characters
void checkChars(char [], int, char*);

// Encrypt plaintext function
void encryptPT(char [], char [], char []);

// Decrypt ciphertext function
void decryptCT(char [], char [], char []);


#endif
