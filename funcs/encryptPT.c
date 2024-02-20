/******************* ENCRYPTION FUNCTION ***************************
 * Space char is ASCII 32. Transform to 26 for BOTH plaintext and key
 * Upper case chars are ASCII 65 - 90. Transform to (0 - 25) for BOTH plaintext and key
 * Sum the transformed plaintext and key
 * Mod 27 (0-26 chars) to get the new char
 * If this char is 26, make it the space char (32) otherwise add 65 to make it uppercase */

#include <string.h>
#include "functions.h"

void encryptPT(char plaintext[], char key[], char ciphertext[]) {
	int i, sub1, sub2;
	for (i=0; i < strlen(plaintext); i++) {
		// Downshift plaintext and key char to 0, then mod 27
		if (plaintext[i] == 32) sub1 = 6;
		else sub1 = 65;
		if (key[i] == 32) sub2 = 6;
		else sub2 = 65;
		ciphertext[i] = (plaintext[i] - sub1 + key[i] - sub2) % 27;

		// If ciphertext is 26, make it a space, otherwise (0-25) make it an uppercase letter
		if (ciphertext[i] == 26) ciphertext[i] = 32;
		else ciphertext[i] = ciphertext[i] + 65;
	}
	return;
}
