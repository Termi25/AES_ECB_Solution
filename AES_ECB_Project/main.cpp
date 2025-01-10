#include<stdio.h>
#include<malloc.h>
#include<string.h>
#include<openssl\aes.h>

int determineFileLength(FILE* file) {
	fseek(file, 0, SEEK_END);
	int length = ftell(file);
	fseek(file, 0, SEEK_SET);
	return length;
}

void printString(unsigned char* string, int stringLength) {
	for (int i = 0; i < stringLength; i++) {
		printf_s("%c", string[i]);
	}
	printf_s("\n\n");
}

void printHex(unsigned char* data, int length) {
	for (int i = 0; i < length; i++) {
		printf_s("%02X ", data[i]);
	}
	printf_s("\n\n");
}

int main() {
	FILE* ptFile = fopen("plaintext.txt", "rb");
	FILE* keyFile = fopen("aes.key", "rb");
	if (ptFile != NULL && keyFile != NULL) {
		int ptSize = determineFileLength(ptFile);
		unsigned char* ptInput = (unsigned char*)malloc(ptSize);
		fread_s(ptInput, ptSize, 1, ptSize, ptFile);

		printf_s("Plaintext value: ");
		printString(ptInput, ptSize);

		int keySize = determineFileLength(keyFile);
		unsigned char* keyInput = (unsigned char*)malloc(keySize);
		fread_s(keyInput, keySize, 1, keySize, keyFile);

		printf_s("Key value: ");
		printHex(keyInput, keySize);

		int totalBlockSize = (ptSize / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
		if (ptSize % AES_BLOCK_SIZE != 0) {
			totalBlockSize += AES_BLOCK_SIZE;
		}

		unsigned char* ctOutput = (unsigned char*)malloc(totalBlockSize);
		AES_KEY aes_key;
		AES_set_encrypt_key(keyInput, keySize * 8, &aes_key);

		for (int i = 0; i < ptSize; i += AES_BLOCK_SIZE) {
			AES_encrypt(ptInput + i, ctOutput + i, &aes_key);
		}

		printf_s("Encrypted value: ");
		printHex(ctOutput, totalBlockSize);

		unsigned char* ptOutput = (unsigned char*)malloc(ptSize);
		AES_set_decrypt_key(keyInput, keySize * 8, &aes_key);
		for (int i = 0; i < totalBlockSize - AES_BLOCK_SIZE; i+=AES_BLOCK_SIZE) {
			AES_decrypt(ctOutput+i, ptOutput+i, &aes_key);
		}

		unsigned char buffer[AES_BLOCK_SIZE];
		AES_decrypt(ctOutput + totalBlockSize - AES_BLOCK_SIZE, buffer, &aes_key);
		for (int i =0 ; i < ptSize - (totalBlockSize - AES_BLOCK_SIZE); i++) {
			ptOutput[totalBlockSize - AES_BLOCK_SIZE + i] = buffer[i];
		}

		printf_s("Decrypted value: ");
		printString(ptOutput, ptSize);

		if (memcmp(ptInput, ptOutput, ptSize) == 0) {
			printf_s("Decryption process successful.\n\n");
		}
		else {
			printf_s("Decryption process failed.\n\n");
		}

		free(ptOutput);
		free(ctOutput);
		free(keyInput);
		free(ptInput);
		fclose(keyFile);
		fclose(ptFile);
	}
	return 0;
}