#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>

#define KEY_LEN crypto_secretstream_xchacha20poly1305_KEYBYTES

int derive_key_from_passwd(unsigned char* key, unsigned long long keylen, const unsigned char* const salt, const char* const password) {
	if (crypto_pwhash
		(key, keylen, password, strlen(password), salt,
		crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
		crypto_pwhash_ALG_DEFAULT) != 0)
	{
		// Out Of Memory
		return 1;
	}

	return 0;
}

#define CHUNK_SIZE 4096

void encrypt_file(const char* input_file, const char* output_file, const char* password)
{
	unsigned char buf_in[CHUNK_SIZE];
	unsigned char buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	FILE* fp_in;
	FILE* fp_out;
	unsigned long long out_len;
	size_t rlen;
	int eof;
	unsigned char tag;
	
	unsigned char key[KEY_LEN];
	unsigned char salt[crypto_pwhash_SALTBYTES];
	
	
	if ((fp_in = fopen(input_file, "rb")) == NULL) {
		perror(input_file);
		exit(1);
	}
	
	if ((fp_out = fopen(output_file, "wb")) == NULL) {
		perror(output_file);
		exit(1);
	}
	
	// Generate a crypto random salt, This will be placed at the beginning of the file so it can be appended
	// to the password given on decryption to allow derivation of the same key
	randombytes_buf(salt, sizeof salt);
	
	// Derive a key from the password and random salt
	if (derive_key_from_passwd(key, sizeof key, salt, password) != 0) {
		fprintf(stderr, "Failed to derive key: Out Of Memory\n");
		fflush(stderr);
		goto error;
	}

	// Write the salt to the start of the file
	fwrite(salt, 1, sizeof salt, fp_out);
	
	
	crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
	fwrite(header, 1, sizeof header, fp_out);
	do {
		rlen = fread(buf_in, 1, sizeof buf_in, fp_in);
		eof = feof(fp_in);
		tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
		crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
													NULL, 0, tag);
		fwrite(buf_out, 1, (size_t) out_len, fp_out);
	} while (!eof);

	fclose(fp_in);
	fclose(fp_out);
	return;

// Clean up after an error by closing the open file descriptors and
// returning exit code 1 from the program
error:
	fclose(fp_in);
	fclose(fp_out);
	exit(1);
}


void decrypt_file(const char* input_file, const char* output_file, const char* password)
{
	unsigned char buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
	unsigned char buf_out[CHUNK_SIZE];
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	FILE* fp_in;
	FILE* fp_out;
	unsigned long long out_len;
	size_t rlen;
	int eof;
	unsigned char tag;

	unsigned char key[KEY_LEN];
	unsigned char salt[crypto_pwhash_SALTBYTES];

	
	if ((fp_in = fopen(input_file, "rb")) == NULL) {
		perror(input_file);
		exit(1);
	}

	if ((fp_out = fopen(output_file, "wb")) == NULL) {
		perror(output_file);
		exit(1);
	}

	// Read the salt placed at the start of the file
	size_t salt_bytes_read = fread(salt, 1, crypto_pwhash_SALTBYTES, fp_in);
	if (salt_bytes_read != crypto_pwhash_SALTBYTES) {
		fprintf(stderr, "%s: Unexpected EOF whilst reading salt bytes.\n", input_file);
		fflush(stderr);
		goto error;
	}

	// Derive a key based on the salt and the password
	if (derive_key_from_passwd(key, sizeof key, salt, password) != 0) {
		fprintf(stderr, "Failed to derive key: Out Of Memory\n");
		fflush(stderr);
		goto error;
	}

	__attribute__((unused)) size_t _bytes_read = fread(header, 1, sizeof header, fp_in);
	if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
		fprintf(stderr, "%s: Incomplete header\n", input_file);
		fflush(stderr);
		goto error;
	}

	do {
		rlen = fread(buf_in, 1, sizeof buf_in, fp_in);
		eof = feof(fp_in);
		if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
														buf_in, rlen, NULL, 0) != 0)
		{
			fprintf(stderr, "%s: Corrupted chunk or wrong password\n", input_file);
			fflush(stderr);
			goto error;
		}

		if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
			if (!eof) {
				fprintf(stderr, "%s: End of stream reached before the end of the file\n", input_file);
				fflush(stderr);
				goto error;
			}
		}
		else {
			if (eof) {
				fprintf(stderr, "%s: End of file reached before the end of the stream\n", input_file);
				fflush(stderr);
				goto error;
			}
		}
		fwrite(buf_out, 1, (size_t) out_len, fp_out);
	} while (!eof);

	fclose(fp_in);
	fclose(fp_out);
	return;

// Clean up after an error by closing the open file descriptors and
// returning exit code 1 from the program
error:
	fclose(fp_in);
	fclose(fp_out);
	exit(1);
}
