/********************************************************************
Class: CS 344 - Operating Systems
Program: Program 4 OTP (One-Time Pads) - otp_enc.c
Author: KC
Date: June 5 2018
Description: otp_enc.c acts as the client and connects to the server
otp_enc_d. Sends a request to encrypt a plaintext message using a key.
It verifies the key before sending and receives ciphertext back from otp_enc_d.
**********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include "functions.h"
#include "checkChars.c"

#define MAX_SIZE 80000
#define READ_SIZE 10
#define HOST_NAME "localhost"


int main(int argc, char *argv[]) {

	// Verify input format
	if (argc != 4) { fprintf(stderr,"USAGE: %s plaintext key port\n", argv[0]); exit(0); } // Check usage & args

	// Open plaintext file
	char buffPT[MAX_SIZE];
	memset(buffPT, '\0', sizeof(buffPT));
	int plainTextFD = open(argv[1], O_RDONLY);
	if (plainTextFD < 0) error("CLIENT: ERROR opening plaintext.\n");

	// Read plainText into buffPT, get bytesReadPT
	int bytesReadPT = read(plainTextFD, buffPT, sizeof(buffPT));
	if (bytesReadPT < 0) error("CLIENT: ERROR occurred in read for plaintext.\n");
	bytesReadPT--; // Decrement bytesRead to remove newline
	buffPT[bytesReadPT] = '\0'; // Remove trailing newline
	close(plainTextFD);

	// Verify plaintext characters
	checkChars(buffPT, bytesReadPT, argv[1]);

	// Open key file, read into buffKEY, get bytesReadKey
	char buffKEY[MAX_SIZE];
	memset(buffKEY, '\0', sizeof(buffKEY));
	int keyFD = open(argv[2], O_RDONLY);
	if (keyFD < 0) error("CLIENT: ERROR opening key.\n");
	int bytesReadKEY = read(keyFD, buffKEY, sizeof(buffKEY));
	if (bytesReadKEY < 0) error("CLIENT: ERROR occurred in read for the key.\n");
	bytesReadKEY--; // Decrement bytesRead to remove newline
	buffKEY[bytesReadKEY] = '\0'; // Remove trailing newline
	close(keyFD);

	// Verify key characters
	checkChars(buffKEY, bytesReadKEY, argv[2]);

	// Verify that key is at least as long as plaintext
	if (bytesReadKEY < bytesReadPT) {
		fprintf(stderr, "CLIENT: ERROR Key is shorter than plaintext!\n");
		exit(1);
	}

	// Initialize variables for connecting socket to server
	int socketFD, portNumber, charsWritten, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[3]); // Get the port number, convert to int from char*
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverHostInfo = gethostbyname(HOST_NAME); // Convert the machine name into a special form of address
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(0); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (socketFD < 0) error("CLIENT: ERROR opening socket");

	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
		error("CLIENT: ERROR connecting");

	// Perform handshake, send "ENC" to server
	char readBuffer[READ_SIZE];
	memset(readBuffer, '\0', sizeof(readBuffer));
	sprintf(readBuffer, "ENC");
	charsWritten = send(socketFD, readBuffer, 3, 0); // Write to the server
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");

	// Get return message from server
	memset(readBuffer, '\0', sizeof(readBuffer)); // Clear out the readBuffer again for reuse
	charsRead = recv(socketFD, readBuffer, 2, 0); // Read data from the socket, leaving \0 at end
	if (charsRead < 0) error("CLIENT: ERROR reading from socket");
	if (strncmp(readBuffer, "##", 2) == 0) {
		fprintf(stderr, "CLIENT: ERROR connected to the wrong server on port %d\n", portNumber);
		close(socketFD);
		exit(2);
	}

	// Send plaintext to server
	charsWritten = send(socketFD, buffPT, strlen(buffPT), 0); // Write to the server
	if (charsWritten < 0) {
		error("CLIENT: ERROR writing to socket");
	}
	if (charsWritten < strlen(buffPT)) {
		printf("CLIENT: WARNING: Not all data written to socket!\n");
	}

	// Send spacer "$$" between plaintext and key
	char* spacer = "$$";
	charsWritten = send(socketFD, spacer, 2, 0);
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");

	// Call recv() between send calls to block so don't combine with key, don't care about contents
	memset(readBuffer, '\0', sizeof(readBuffer)); // Clear out the readBuffer again for reuse
	charsRead = recv(socketFD, readBuffer, 2, 0); // Read data from the socket, leaving \0 at end
	if (charsRead < 0) error("CLIENT: ERROR reading from socket");

	// Send key to server
	charsWritten = send(socketFD, buffKEY, strlen(buffKEY), 0); // Write to the server
	if (charsWritten < 0) {
		error("CLIENT: ERROR writing to socket");
	}
	if (charsWritten < strlen(buffKEY) ) {
		printf("CLIENT: WARNING: Not all data written to socket!\n");
	}

	// Send end characters "!!" to server
	char* endChars = "!!";
	charsWritten = send(socketFD, endChars, 2, 0);
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");

	// Get ciphertext back from server, same length as plaintext
	char buffCIPHER[MAX_SIZE];
	memset(buffCIPHER, '\0', sizeof(buffCIPHER)); // Clear out the buffCIPHER
	memset(readBuffer, '\0', sizeof(readBuffer)); // Clear out the readBuffer again for reuse
	while ( strlen(buffCIPHER) < strlen(buffPT) ) {
		// Get the message from the client
		memset(readBuffer, '\0', sizeof(readBuffer));
		charsRead = recv(socketFD, readBuffer, sizeof(readBuffer) - 1, 0); // Read the client's message from the socket
		if (charsRead < 0) error("CLIENT: ERROR reading from socket");

		// Append readBuffer onto buffKEY
		strcat(buffCIPHER, readBuffer);
	}

	printf("%s\n", buffCIPHER); fflush(stdout);

	close(socketFD); // Close the socket
	return 0;
}
