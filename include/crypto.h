#ifndef CRYPTO_H
#define CRYPTO_H

int derive_key_from_passwd(unsigned char* key, unsigned long long keylen, const unsigned char* const salt, const char* const password);

void encrypt_file(const char* input_file, const char* output_file, const char* password);
void decrypt_file(const char* input_file, const char* output_file, const char* password);

#endif
