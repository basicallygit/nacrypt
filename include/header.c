#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "header.h"

const unsigned char NACRYPT_MAGIC[4] = {0x4E, 0x41, 0x1F, 0xF0};

int parse_header(NacryptHeader* header, FILE* fileptr) {
	if (fileptr == NULL) {
		fprintf(stderr, "FATAL: parse_header() was passed NULL\n");
		fflush(stderr);
		return -99;
	}

	unsigned char header_buffer[HEADER_SIZE];
	size_t bytes_read = fread(header_buffer, 1, HEADER_SIZE, fileptr);

	if (bytes_read != HEADER_SIZE) return ERR_NOT_NACRYPT_FILE;
	// Make sure first 4 bytes match expected magic
	if (memcmp(header_buffer, NACRYPT_MAGIC, 4) != 0) return ERR_NOT_NACRYPT_FILE;
	
	switch (header_buffer[HEADER_VERSION_INDEX]) {
		case 1:
			break;
		default:
			return ERR_UNKNOWN_HEADER_VERSION;
	}

	switch (header_buffer[KDF_ALGORITHM_INDEX]) {
		case KDF_ALGORITHM_ARGON2ID:
			break;
		default:
			return ERR_UNKNOWN_KDF_ALGORITHM;
	}
	
	switch (header_buffer[ENC_ALGORITHM_INDEX]) {
		case ENC_ALGORITHM_CHACHA20POLY1305:
			break;
		default:
			return ERR_UNKNOWN_ENC_ALGORITHM;
	}

	if (header_buffer[RESERVED_INDEX] != 0) return ERR_NOT_NACRYPT_FILE;

	memcpy(header->magic, NACRYPT_MAGIC, 4);
	header->headerversion = header_buffer[HEADER_VERSION_INDEX];
	header->kdf_algorithm = header_buffer[KDF_ALGORITHM_INDEX];
	header->enc_algorithm = header_buffer[ENC_ALGORITHM_INDEX];
	header->reserved = 0;

	return 0;
}

int init_header(NacryptHeader* header, unsigned char kdf_algorithm, unsigned char enc_algorithm) {
	switch (kdf_algorithm) {
		case KDF_ALGORITHM_ARGON2ID:
			break;
		default:
			return ERR_UNKNOWN_KDF_ALGORITHM;
	}

	switch (enc_algorithm) {
		case ENC_ALGORITHM_CHACHA20POLY1305:
			break;
		default:
			return ERR_UNKNOWN_ENC_ALGORITHM;
	}

	memcpy(header->magic, NACRYPT_MAGIC, 4);
	header->headerversion = 1;
	header->kdf_algorithm = kdf_algorithm;
	header->enc_algorithm = enc_algorithm;
	header->reserved = 0;

	return 0;
}

int write_header(NacryptHeader* header, FILE* fileptr) {
	if (fileptr == NULL) {
		fprintf(stderr, "FATAL: write_header() was passed NULL\n");
		fflush(stderr);
		return -1;
	}
	
	if (fwrite(header->magic, 1, 4, fileptr) != 4) return -1;
	putc(header->headerversion, fileptr);
	putc(header->kdf_algorithm, fileptr);
	putc(header->enc_algorithm, fileptr);
	putc(header->reserved, fileptr);

	return 0;
}
