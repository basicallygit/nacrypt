#ifndef NACRYPT_CRYPTO_H
#define NACRYPT_CRYPTO_H

#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>

#define MAX_PASSWORD_SIZE 512
#define SALT_LEN 32

#define NACRYPT_PUBKEY_PREFIX "nacrypt_pubkey_"
#define NACRYPT_PUBKEY_PREFIX_LEN (sizeof(NACRYPT_PUBKEY_PREFIX) - 1)

#define SECRET_KEY_PATH "/.nacrypt/private.key"
#define PUBLIC_KEY_PATH "/.nacrypt/public.key"
#define NACRYPT_DIR_PATH "/.nacrypt"

static const unsigned char NACRYPT_MAGIC[4] = {0x4E, 0x41, 0x1F, 0xF0};
#define SYMMETRY_ASYMMETRIC 1
#define SYMMETRY_SYMMETRIC 0

#define NACRYPT_KDF_ALG_DEFAULT crypto_pwhash_ALG_ARGON2ID13
#define NACRYPT_OPSLIMIT_DEFAULT 4			// OPSLIMIT_SENSITIVE (4 passes)
#define NACRYPT_MEMLIMIT_DEFAULT 1073741824 // MEMLIMIT_SENSITIVE (1GB)

int derive_key(unsigned char* key, unsigned long long keylen,
			   const unsigned char* const salt, const char* const password,
			   unsigned long long opslimit, size_t memlimit);

int generate_keypair(void);

int dearmor_public_key(const char* const armored_public_key,
					   unsigned char* public_key_buf);

int write_secret_key(FILE* fp_secret_key, const unsigned char* const secret_key,
					 const char* const password);

int read_secret_key(FILE* fp_secret_key, unsigned char* secret_key_buf,
					const char* const password);

int encrypt_file_symmetric(FILE* input_file, FILE* output_file,
						   const char* const password);
int encrypt_file_asymmetric(FILE* input_file, FILE* output_file,
							const unsigned char* const recipient_pubkey);
int encrypt_file(FILE* input_file, FILE* output_file,
				 const unsigned char* const key);

int decrypt_file_symmetric(FILE* input_file, FILE* output_file,
						   const char* const password);
int decrypt_file_asymmetric(FILE* input_file, FILE* output_file,
							const unsigned char* const secret_key);
int decrypt_file(FILE* input_file, FILE* output_file,
				 const unsigned char* const key);

#endif // !defined(NACRYPT_CRYPTO_H)
