/********************* DECRYPTION FUNCTION ***************************
 * Space char is ASCII 32. Transform to 26 for BOTH ciphertext and key
 * Upper case chars are ASCII 65 - 90. Transform to (0 - 25) for BOTH ciphertext and key
 * Subtract the transformed key from the transformed ciphertext
 * Mod 27 (0-26 chars) to get the new char
 * If this char is 26, make it the space char (32) otherwise add 65 to make it uppercase */

#include <string.h>
#include "functions.h"

void decryptCT(char ciphertext[], char key[], char plaintext[]) {
	int i, sub1, sub2;
	for (i=0; i < strlen(ciphertext); i++) {
		// Downshift ciphertext and key char to 0, then mod 27
		if (ciphertext[i] == 32) sub1 = 6;
		else sub1 = 65;
		if (key[i] == 32) sub2 = 6;
		else sub2 = 65;
		plaintext[i] = (ciphertext[i] - sub1 - (key[i] - sub2));
		if (plaintext[i] < 0) plaintext[i] = ((plaintext[i] + 27) % 27);
		else plaintext[i] = (plaintext[i] % 27);

		// If plaintext is 26, make it a space, otherwise (0-25) make it an uppercase letter
		if (plaintext[i] == 26) plaintext[i] = 32;
		else plaintext[i] = plaintext[i] + 65;
	}
	return;
}
