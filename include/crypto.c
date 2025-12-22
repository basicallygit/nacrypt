#include <stdbool.h>
#include <sodium.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "crypto.h"
#include "utils.h"

#define CHUNK_SIZE 4096
#define KEY_LEN crypto_secretstream_xchacha20poly1305_KEYBYTES

bool derive_key_from_password(unsigned char* key, unsigned long long keylen, const unsigned char* const salt, const char* const password, unsigned long long opslimit, size_t memlimit) {
	if (crypto_pwhash
		(key, keylen, password, strlen(password), salt,
		opslimit, memlimit,
		NACRYPT_KDF_ALG_DEFAULT) != 0)
	{
		return false;
	}
	return true;
}

bool encrypt_file(FILE* input_file, FILE* output_file, const char* password, unsigned long long opslimit, size_t memlimit) {
	if (input_file == NULL || output_file == NULL) return false;
	unsigned char buf_in[CHUNK_SIZE];
	unsigned char buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state state;
	unsigned long long out_len;
	size_t rlen;
	int eof;
	unsigned char tag;
	unsigned char key[KEY_LEN];
	unsigned char salt[SALT_LEN];

	randombytes_buf(salt, SALT_LEN);
	if (!derive_key_from_password(key, KEY_LEN, salt, password, opslimit, memlimit)) {
		eprintf("Failed to derive key: Out-of-memory\n");
		return false;
	}

	fwrite(salt, 1, SALT_LEN, output_file);
	
	crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
	fwrite(header, 1, sizeof header, output_file);
	
	do {
		rlen = fread(buf_in, 1, sizeof buf_in, input_file);
		eof = feof(input_file);
		tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
		crypto_secretstream_xchacha20poly1305_push(&state, buf_out, &out_len, buf_in, rlen, NULL, 0, tag);
		if (fwrite(buf_out, 1, (size_t)out_len, output_file) < (size_t)out_len) {
			perror("fwrite");
			return false;
		}
	} while (!eof);

	return true;
}

bool decrypt_file(FILE* input_file, FILE* output_file, const char* password, unsigned long long opslimit, size_t memlimit) {
	if (input_file == NULL || output_file == NULL) return false;
	unsigned char buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
	unsigned char buf_out[CHUNK_SIZE];
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state state;
	unsigned long long out_len;
	size_t rlen;
	int eof;
	unsigned char tag;
	unsigned char key[KEY_LEN];
	unsigned char salt[SALT_LEN];

	size_t salt_bytes_read = fread(salt, 1, SALT_LEN, input_file);
	if (salt_bytes_read != SALT_LEN) {
		eprintf("FATAL: Unexpected EOF while reading salt\n");
		return false;
	}

	if (!derive_key_from_password(key, KEY_LEN, salt, password, opslimit, memlimit)) {
		eprintf("FATAL: Failed to derive key: Out-of-memory\n");
		return false;
	}

	size_t header_bytes_read = fread(header, 1, sizeof header, input_file);
	if (header_bytes_read != sizeof header
		|| crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) != 0)
	{
		eprintf("FATAL: Incomplete secretstream header (potentially corrupt file?)\n");
		return false;
	}

	do {
		rlen = fread(buf_in, 1, sizeof buf_in, input_file);
		eof = feof(input_file);
		if (crypto_secretstream_xchacha20poly1305_pull(
			&state, buf_out, &out_len, &tag,
			buf_in, rlen, NULL, 0) != 0)
		{
			eprintf("FATAL: Incorrect password or corrupted chunk\n");
			return false;
		}
		
		if (!eof && tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
			eprintf("FATAL: End of secretstream reached before end of file\n");
			return false;
		}
		else if (eof && tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
			eprintf("FATAL: End of file reached before end of secretstream\n");
			return false;
		}

		if (fwrite(buf_out, 1, (size_t)out_len, output_file) < (size_t)out_len) {
			perror("fwrite");
			return false;
		}
	} while (!eof);

	return true;
}
