/********************************************************************
Class: CS 344 - Operating Systems
Program: Program 4 OTP (One-Time Pads) - otp_dec_d.c
Author: KC
Date: June 9 2018
Description: otp_dec_d.c acts as the server daemon, opens a communication
socket with otp_dec and receives a request to decrypt a ciphertext
message using a key. It returns this ciphertext to otp_dec.
**********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "functions.h"
#include "decryptCT.c"

#define SMALL_CHARS 10
#define MAX_CHARS 80000


int main(int argc, char *argv[])
{
	int listenSocketFD, establishedConnectionFD, portNumber, charsRead;
	socklen_t sizeOfClientInfo;
	struct sockaddr_in serverAddress, clientAddress;

	if (argc < 2) { fprintf(stderr,"USAGE: %s port\n", argv[0]); exit(1); } // Check usage & args

	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (listenSocketFD < 0) error("SERVER: ERROR opening socket");

	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to port
		error("SERVER: ERROR on binding");
	listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

	// With the listen socket established, keep spawning off children to handle incoming connections
	while (1) {
		// Accept a connection, blocking if one is not available until one connects
		sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
		establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
		if (establishedConnectionFD < 0) error("SERVER: ERROR on accept");

		// Forking child process after accepting a new connection
		int childExitMethod = -5;
		pid_t childPID;
		childPID = fork();
		switch (childPID) {

			// Error forking off child process
			case -1: {
				error("CLIENT: ERROR forking off child");
				break;
			}

			// Child process. Handles all client communication, closes client file descriptor
			case 0: {
				// Verify that communicating with otp_dec. If receive "DEC" handshake back with "ok"
				// Otherwise should receive "ENC" from encrypt, in which case send "##"
				char readBuffer[SMALL_CHARS]; // Read buffer to recv() data in small chunks
				memset(readBuffer, '\0', sizeof(readBuffer));
				charsRead = recv(establishedConnectionFD, readBuffer, 3, 0);
				if (strncmp(readBuffer, "DEC", 3) == 0) send(establishedConnectionFD, "ok", 2, 0);
				else {
					send(establishedConnectionFD, "##", 2, 0);
					exit(0);
				}

				// Read until receive "$$", marking end of ciphertext
				char buffCT[MAX_CHARS]; // Ciphertext buffer
				memset(buffCT, '\0', MAX_CHARS);
				while (strstr(buffCT, "$$") == NULL) {
					// Get the message from the client
					memset(readBuffer, '\0', sizeof(readBuffer));
					charsRead = recv(establishedConnectionFD, readBuffer, sizeof(readBuffer) - 1, 0); // Read the client's message from the socket
					if (charsRead < 0) error("SERVER: ERROR reading from socket");

					// Append readBuffer onto buffCT
					strcat(buffCT, readBuffer);
				}

				// Remove $$ from ciphertext
				int stopLoc = strstr(buffCT, "$$") - buffCT;
				buffCT[stopLoc] = '\0';

				// Send message to block next recv() call to separate key
				charsRead = send(establishedConnectionFD, "ok", 2, 0);
				if (charsRead < 0) error("SERVER: ERROR writing to socket");

				// Read until receive "!!", marking end of the key
				char buffKEY[MAX_CHARS]; // Key buffer
				memset(buffKEY, '\0', MAX_CHARS);
				while (strstr(buffKEY, "!!") == NULL) {
					// Get the message from the client
					memset(readBuffer, '\0', sizeof(readBuffer));
					charsRead = recv(establishedConnectionFD, readBuffer, sizeof(readBuffer) - 1, 0);
					if (charsRead < 0) error("SERVER: ERROR reading from socket");

					// Append readBuffer onto buffKEY
					strcat(buffKEY, readBuffer);
				}

				// Remove !! from key
				stopLoc = strstr(buffKEY, "!!") - buffKEY;
				buffKEY[stopLoc] = '\0';

				// Produce plaintext from ciphertext and key
				char buffPT[MAX_CHARS];
				memset(buffPT, '\0', sizeof(buffPT));
				decryptCT(buffCT, buffKEY, buffPT);

				// Send plaintext back to the client
				int charSent = 0;
				while (charSent < strlen(buffPT)) {
					charSent = send(establishedConnectionFD, buffPT, strlen(buffPT), 0); // Send  back
				}
				if (charSent < 0) error("SERVER: ERROR writing to socket");

				// Close the client communication socket
				close(establishedConnectionFD);

				// Exit the child process
				exit(0);
				break;
			}

			// Parent process.
			default: {
				// Harvest zombie children
				pid_t anyChild = -5;
				anyChild = waitpid(-1, &childExitMethod, WNOHANG);
				break;
			}
		}
	}

	// Close the listening socket
	close(listenSocketFD);

	return 0;
}
