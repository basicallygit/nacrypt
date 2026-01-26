#include "crypto.h"
#include "utils.h"
#include <errno.h>
#include <sodium.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK_SIZE (64 * 1024)
#define KEY_LEN crypto_secretstream_xchacha20poly1305_KEYBYTES

int derive_key(unsigned char* key, unsigned long long keylen,
			   const unsigned char* const salt, const char* const password,
			   unsigned long long opslimit, size_t memlimit) {
	if (crypto_pwhash(key, keylen, password, strlen(password), salt, opslimit,
					  memlimit, NACRYPT_KDF_ALG_DEFAULT) != 0)
	{
		return -1; // Likely out-of-memory
	}
	return 0;
}

int encrypt_file(FILE* input_file, FILE* output_file, const char* password,
				 unsigned long long opslimit, size_t memlimit) {
	if (input_file == NULL || output_file == NULL)
		return false;
	const size_t BUF_IN_LEN = CHUNK_SIZE;
	const size_t BUF_OUT_LEN =
		CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES;
	unsigned char* buf_in;
	unsigned char* buf_out;
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state state;
	unsigned long long out_len;
	size_t rlen;
	int eof;
	unsigned char tag;
	unsigned char* key; // KEY_LEN, sensitive memory
	unsigned char salt[SALT_LEN];

	key = (unsigned char*)sodium_malloc(KEY_LEN);
	if (key == NULL) {
		perror("FATAL: Failed to securely allocate key: sodium_malloc");
		return -1;
	}

	// buf_in and buf_out likely wont be locked because of lock limit, but it
	// doesnt matter that much
	buf_in = (unsigned char*)sodium_malloc(BUF_IN_LEN);
	if (buf_in == NULL) {
		perror("FATAL: sodium_malloc");
		sodium_free(key);
		return -1;
	}

	buf_out = (unsigned char*)sodium_malloc(BUF_OUT_LEN);
	if (buf_out == NULL) {
		perror("FATAL: sodium_malloc");
		sodium_free(key);
		sodium_free(buf_in);
		return -1;
	}

	randombytes_buf(salt, SALT_LEN);
	puts("Deriving key..");
	if (derive_key(key, KEY_LEN, salt, password, opslimit, memlimit) != 0) {
		eprintf("FATAL: Failed to derive key: Out of memory\n");
		goto error;
	}
	puts("Done");

	if (fwrite(salt, 1, SALT_LEN, output_file) != SALT_LEN) {
		perror("FATAL: fwrite");
		goto error;
	}

	crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
	if (fwrite(header, 1, sizeof header, output_file) != sizeof header) {
		perror("FATAL: fwrite");
		goto error;
	}

	do {
		rlen = fread(buf_in, 1, BUF_IN_LEN, input_file);
		eof = feof(input_file);
		tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
		crypto_secretstream_xchacha20poly1305_push(&state, buf_out, &out_len,
												   buf_in, rlen, NULL, 0, tag);
		if (fwrite(buf_out, 1, (size_t)out_len, output_file) < (size_t)out_len)
		{
			perror("FATAL: fwrite");
			goto error;
		}
	} while (!eof);

	sodium_free(key);
	sodium_free(buf_in);
	sodium_free(buf_out);
	return 0;

error:
	sodium_free(key);
	sodium_free(buf_in);
	sodium_free(buf_out);
	return -1;
}

int decrypt_file(FILE* input_file, FILE* output_file, const char* password,
				 unsigned long long opslimit, size_t memlimit) {
	if (input_file == NULL || output_file == NULL)
		return -1;
	const size_t BUF_IN_LEN =
		CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES;
	const size_t BUF_OUT_LEN = CHUNK_SIZE;
	unsigned char* buf_in;
	unsigned char* buf_out;
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state state;
	unsigned long long out_len;
	size_t rlen;
	int eof;
	unsigned char tag;
	unsigned char* key; // KEY_LEN
	unsigned char salt[SALT_LEN];

	if (fread(salt, 1, SALT_LEN, input_file) != SALT_LEN) {
		eprintf("FATAL: Unexpected EOF while reading salt\n");
		return -1;
	}

	key = (unsigned char*)sodium_malloc(KEY_LEN);
	if (key == NULL) {
		perror("FATAL: Failed to securely allocate key: sodium_malloc");
		return -1;
	}

	// buf_in and buf_out likely wont be locked because of lock limit, but it
	// doesnt matter that much
	buf_in = (unsigned char*)sodium_malloc(BUF_IN_LEN);
	if (buf_in == NULL) {
		perror("FATAL: sodium_malloc");
		sodium_free(key);
		return -1;
	}

	buf_out = (unsigned char*)sodium_malloc(BUF_OUT_LEN);
	if (buf_out == NULL) {
		perror("FATAL: sodium_malloc");
		sodium_free(key);
		sodium_free(buf_in);
		return -1;
	}

	puts("Deriving key..");
	if (derive_key(key, KEY_LEN, salt, password, opslimit, memlimit) != 0) {
		eprintf("FATAL: Failed to derive key: Out of memory\n");
		goto error;
	}
	puts("Done");

	size_t header_bytes_read = fread(header, 1, sizeof header, input_file);
	if (header_bytes_read != sizeof header ||
		crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) !=
			0)
	{
		eprintf("FATAL: Incomplete secretstream header (corrupt file?)\n");
		goto error;
	}

	do {
		rlen = fread(buf_in, 1, BUF_IN_LEN, input_file);
		eof = feof(input_file);
		if (crypto_secretstream_xchacha20poly1305_pull(
				&state, buf_out, &out_len, &tag, buf_in, rlen, NULL, 0) != 0)
		{
			eprintf("FATAL: Incorrect password or corrupted chunk\n");
			goto error;
		}

		if (!eof && tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
			eprintf("FATAL: End of secretstream reached before end of file\n");
			goto error;
		} else if (eof &&
				   tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL)
		{
			eprintf("FATAL: End of file reached before end of secretstream\n");
			goto error;
		}

		if (fwrite(buf_out, 1, (size_t)out_len, output_file) < (size_t)out_len)
		{
			perror("FATAL: fwrite");
			goto error;
		}
	} while (!eof);

	sodium_free(key);
	sodium_free(buf_in);
	sodium_free(buf_out);
	return 0;

error:
	sodium_free(key);
	sodium_free(buf_in);
	sodium_free(buf_out);
	return -1;
}
