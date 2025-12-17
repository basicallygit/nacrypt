#ifndef NACRYPT_HEADER_H
#define NACRYPT_HEADER_H

#include <stdio.h>

#define HEADER_SIZE 8
extern const unsigned char NACRYPT_MAGIC[4];
#define HEADER_VERSION_INDEX 4
#define KDF_ALGORITHM_INDEX 5
#define ENC_ALGORITHM_INDEX 6
#define RESERVED_INDEX 7

#define KDF_ALGORITHM_ARGON2ID 0

#define ENC_ALGORITHM_CHACHA20POLY1305 0

#define ERR_NOT_NACRYPT_FILE -1
#define ERR_UNKNOWN_HEADER_VERSION -2
#define ERR_UNKNOWN_KDF_ALGORITHM -3
#define ERR_UNKNOWN_ENC_ALGORITHM -4

typedef struct {
	unsigned char magic[4];
	unsigned char headerversion;
	unsigned char kdf_algorithm;
	unsigned char enc_algorithm;
	unsigned char reserved;
} NacryptHeader;

int parse_header(NacryptHeader* header, FILE* fileptr);
int init_header(NacryptHeader* header, unsigned char kdf_algorithm, unsigned char enc_algorithm);
int write_header(NacryptHeader* header, FILE* fileptr);

#endif //NACRYPT_HEADER_H
