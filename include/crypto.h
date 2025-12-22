#ifndef NACRYPT_CRYPTO_H
#define NACRYPT_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <sodium.h>

#define SALT_LEN 32

#define NACRYPT_KDF_ALG_DEFAULT crypto_pwhash_ALG_ARGON2ID13
#define NACRYPT_OPSLIMIT_DEFAULT 3
#define NACRYPT_MEMLIMIT_DEFAULT 268435456

int derive_key(unsigned char* key, unsigned long long keylen, const unsigned char* const salt, const char* const password);
bool encrypt_file(FILE* input_file, FILE* output_file, const char* password, unsigned long long opslimit, size_t memlimit);
bool decrypt_file(FILE* input_file, FILE* output_file, const char* password, unsigned long long opslimit, size_t memlimit);

#endif // !defined(NACRYPT_CRYPTO_H)
