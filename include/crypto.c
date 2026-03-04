#include "crypto.h"
#include "utils.h"
#include "version.h"
#include <arpa/inet.h> // htonl, ntohl
#include <errno.h>
#include <sodium.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK_SIZE (64 * 1024)
#define KEY_LEN crypto_secretstream_xchacha20poly1305_KEYBYTES
const unsigned char HEADER_VERSION_BYTE = NACRYPT_HEADER_VERSION;

int derive_key(unsigned char* key, unsigned long long keylen,
			   const unsigned char* const salt, const char* const password,
			   unsigned long long opslimit, size_t memlimit) {
	printf("Deriving key from password.. ");
	fflush(stdout);
	if (crypto_pwhash(key, keylen, password, strlen(password), salt, opslimit,
					  memlimit, NACRYPT_KDF_ALG_DEFAULT) != 0)
	{
		return -1; // Likely out-of-memory
	}
	puts("Done");
	return 0;
}

// Cannot be used inside sandbox as calls fopen()
int generate_keypair(void) {
	const char* homedir = getenv("HOME");
	if (homedir == NULL) {
		eprintf("FATAL: Failed to get home directory from $HOME\n");
		return -1;
	}

	switch (make_dir_at(homedir, NACRYPT_DIR_PATH)) {
	case 0:
		puts("[INFO] Created directory ~/.nacrypt");
		break;
	case 1:
		// EEXIST
		break;
	default:
		perror("FATAL: Failed to create ~/.nacrypt");
		return -1;
	}

	FILE* fp_secret_key = fopen_from(homedir, SECRET_KEY_PATH, "wb");
	if (fp_secret_key == NULL) {
		eprintf("FATAL: Failed to open %s%s: %s\n", homedir, SECRET_KEY_PATH,
				strerror(errno));
		return -1;
	}

	unsigned char public_key[crypto_box_PUBLICKEYBYTES];
	unsigned char* secret_key = sodium_malloc(crypto_box_SECRETKEYBYTES);
	if (secret_key == NULL) {
		perror("FATAL: sodium_malloc()");
		safe_fclose(fp_secret_key);
		return -1;
	}

	crypto_box_keypair(public_key, secret_key);

	printf("Please create a password to protect your private key on disk: ");
	fflush(stdout);
	char* password = read_password(MAX_PASSWORD_SIZE);
	if (password == NULL) {
		// read_password() already prints what went wrong
		safe_sodium_free(secret_key);
		safe_fclose(fp_secret_key);
		return -1;
	}

	if (write_secret_key(fp_secret_key, secret_key, password) != 0) {
		safe_sodium_free(secret_key);
		safe_sodium_free(password);
		safe_fclose(fp_secret_key);
		return -1;
	}
	safe_sodium_free(secret_key);
	safe_sodium_free(password);
	safe_fclose(fp_secret_key);

	// Armor the public key to be human readable (nacrypt_pubkey_<base64>)
	const size_t b64_len = sodium_base64_ENCODED_LEN(
		crypto_box_SECRETKEYBYTES, sodium_base64_VARIANT_ORIGINAL);
	const size_t armored_pubkey_len = NACRYPT_PUBKEY_PREFIX_LEN + b64_len;
	char armored_pubkey[armored_pubkey_len];
	memcpy(armored_pubkey, NACRYPT_PUBKEY_PREFIX, NACRYPT_PUBKEY_PREFIX_LEN);
	sodium_bin2base64(armored_pubkey + NACRYPT_PUBKEY_PREFIX_LEN, b64_len,
					  public_key, crypto_box_PUBLICKEYBYTES,
					  sodium_base64_VARIANT_ORIGINAL);

	printf("Your public key: %s\n", armored_pubkey);

	FILE* fp_public_key = fopen_from(homedir, PUBLIC_KEY_PATH, "wb");
	if (fp_public_key == NULL) {
		eprintf("FATAL: Failed to open %s%s: %s\n", homedir, PUBLIC_KEY_PATH,
				strerror(errno));
		return -1;
	}

	if (fwrite(armored_pubkey, armored_pubkey_len - 1, 1, fp_public_key) != 1 ||
		fputc('\n', fp_public_key) == EOF)
	{
		eprintf("FATAL: Failed to write public key to %s%s: %s\n", homedir,
				PUBLIC_KEY_PATH, strerror(errno));
		safe_fclose(fp_public_key);
		return -1;
	}

	safe_fclose(fp_public_key);

	printf("Saved public and private key to %s%s\n", homedir, NACRYPT_DIR_PATH);
	fflush(stdout);
	return 0;
}

// Recover the public key if the user has lost it.
// Cannot be used inside sandbox as calls fopen()
int regenerate_public_key(void) {
	const char* homedir = getenv("HOME");
	if (homedir == NULL) {
		eprintf("FATAL: Failed to get home directory from $HOME\n");
		return -1;
	}

	FILE* fp_secret_key = fopen_from(homedir, SECRET_KEY_PATH, "rb");
	if (fp_secret_key == NULL) {
		eprintf("FATAL: Failed to open %s%s: %s\n", homedir, SECRET_KEY_PATH,
				strerror(errno));
		return -1;
	}

	unsigned char* secret_key = sodium_malloc(crypto_box_SECRETKEYBYTES);
	if (secret_key == NULL) {
		perror("FATAL: sodium_malloc()");
		safe_fclose(fp_secret_key);
		return -1;
	}

	printf("Enter password for %s%s: ", homedir, SECRET_KEY_PATH);
	fflush(stdout);
	char* password = read_password(MAX_PASSWORD_SIZE);
	if (password == NULL) {
		// read_password() already prints what went wrong
		safe_sodium_free(secret_key);
		safe_fclose(fp_secret_key);
		return -1;
	}

	if (read_secret_key(fp_secret_key, secret_key, password) != 0) {
		safe_sodium_free(secret_key);
		safe_sodium_free(password);
		safe_fclose(fp_secret_key);
		return -1;
	}
	safe_sodium_free(password);

	unsigned char public_key[crypto_box_PUBLICKEYBYTES];
	// Get the public key back from the secret key
	crypto_scalarmult_base(public_key, secret_key);

	// Not needed anymore
	safe_sodium_free(secret_key);
	safe_fclose(fp_secret_key);

	// Armor the public key to be human readable (nacrypt_pubkey_<base64>)
	const size_t b64_len = sodium_base64_ENCODED_LEN(
		crypto_box_SECRETKEYBYTES, sodium_base64_VARIANT_ORIGINAL);
	const size_t armored_pubkey_len = NACRYPT_PUBKEY_PREFIX_LEN + b64_len;
	char armored_pubkey[armored_pubkey_len];
	memcpy(armored_pubkey, NACRYPT_PUBKEY_PREFIX, NACRYPT_PUBKEY_PREFIX_LEN);
	sodium_bin2base64(armored_pubkey + NACRYPT_PUBKEY_PREFIX_LEN, b64_len,
					  public_key, crypto_box_PUBLICKEYBYTES,
					  sodium_base64_VARIANT_ORIGINAL);

	printf("Your public key: %s\n", armored_pubkey);

	FILE* fp_public_key = fopen_from(homedir, PUBLIC_KEY_PATH, "wb");
	if (fp_public_key == NULL) {
		eprintf("FATAL: Failed to open %s%s: %s\n", homedir, PUBLIC_KEY_PATH,
				strerror(errno));
		return -1;
	}

	if (fwrite(armored_pubkey, armored_pubkey_len - 1, 1, fp_public_key) != 1 ||
		fputc('\n', fp_public_key) == EOF)
	{
		eprintf("FATAL: Failed to write public key to %s%s: %s\n", homedir,
				PUBLIC_KEY_PATH, strerror(errno));
		safe_fclose(fp_public_key);
		return -1;
	}

	safe_fclose(fp_public_key);

	printf("Saved public key to %s%s\n", homedir, PUBLIC_KEY_PATH);
	fflush(stdout);
	return 0;
}

int dearmor_public_key(const char* const armored_public_key,
					   unsigned char* public_key_buf) {
	if (armored_public_key == NULL || public_key_buf == NULL)
		return -1;

	// Format nacrypt_pubkey_<base64 public key bytes>
	const size_t b64_len = sodium_base64_ENCODED_LEN(
		crypto_box_SECRETKEYBYTES, sodium_base64_VARIANT_ORIGINAL);
	const size_t armored_pubkey_len = NACRYPT_PUBKEY_PREFIX_LEN + b64_len;

	if (strlen(armored_public_key) != armored_pubkey_len - 1)
		return -1;

	if (memcmp(armored_public_key, NACRYPT_PUBKEY_PREFIX,
			   NACRYPT_PUBKEY_PREFIX_LEN) != 0)
	{
		// Didnt start with nacrypt_pubkey_
		return -1;
	}

	const char* b64_public_key = armored_public_key + NACRYPT_PUBKEY_PREFIX_LEN;

	size_t bin_len;
	if (sodium_base642bin(public_key_buf, crypto_box_PUBLICKEYBYTES,
						  b64_public_key, strlen(b64_public_key), NULL,
						  &bin_len, NULL,
						  sodium_base64_VARIANT_ORIGINAL) != 0 ||
		bin_len != crypto_box_PUBLICKEYBYTES)
	{
		return -1;
	}

	return 0;
}

int write_secret_key(FILE* fp_secret_key, const unsigned char* const secret_key,
					 const char* const password) {
	if (fp_secret_key == NULL || secret_key == NULL || password == NULL)
		return -1;
	const uint32_t opslimit = NACRYPT_OPSLIMIT_DEFAULT;
	const uint32_t memlimit = NACRYPT_MEMLIMIT_DEFAULT;
	const uint32_t net_opslimit = htonl(opslimit);
	const uint32_t net_memlimit = htonl(memlimit);
	unsigned char salt[SALT_LEN];
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	// crypto_box secret key inside a crypto_secretbox
	const size_t ciphertext_len =
		crypto_secretbox_MACBYTES + crypto_box_SECRETKEYBYTES;
	unsigned char ciphertext[ciphertext_len];

	randombytes_buf(salt, sizeof salt);
	randombytes_buf(nonce, sizeof nonce);

	unsigned char* box_key = sodium_malloc(crypto_secretbox_KEYBYTES);
	if (box_key == NULL) {
		perror("FATAL: sodium_malloc()");
		return -1;
	}

	if (derive_key(box_key, crypto_secretbox_KEYBYTES, salt, password,
				   (unsigned long long)opslimit, (size_t)memlimit) != 0)
	{
		eprintf("FATAL: Failed to derive key\n");
		safe_sodium_free(box_key);
		return -1;
	}

	if (crypto_secretbox_easy(ciphertext, secret_key, crypto_box_SECRETKEYBYTES,
							  nonce, box_key) != 0)
	{
		// Shouldn't happen
		safe_sodium_free(box_key);
		return -1;
	}
	sodium_free(box_key);

	if (fwrite(&net_opslimit, sizeof(net_opslimit), 1, fp_secret_key) != 1 ||
		fwrite(&net_memlimit, sizeof(net_memlimit), 1, fp_secret_key) != 1 ||
		fwrite(salt, sizeof(salt), 1, fp_secret_key) != 1 ||
		fwrite(nonce, sizeof(nonce), 1, fp_secret_key) != 1 ||
		fwrite(ciphertext, ciphertext_len, 1, fp_secret_key) != 1)
	{
		perror("FATAL: Failed to write private key to disk");
		return -1;
	}

	return 0;
}

int read_secret_key(FILE* fp_secret_key, unsigned char* secret_key_buf,
					const char* const password) {
	if (fp_secret_key == NULL || password == NULL)
		return -1;
	uint32_t opslimit = NACRYPT_OPSLIMIT_DEFAULT;
	uint32_t memlimit = NACRYPT_MEMLIMIT_DEFAULT;
	unsigned char salt[SALT_LEN];
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	// crypto_box secret key inside a crypto_secretbox
	const size_t ciphertext_len =
		crypto_secretbox_MACBYTES + crypto_box_SECRETKEYBYTES;
	unsigned char ciphertext[ciphertext_len];

	if (fread(&opslimit, sizeof(opslimit), 1, fp_secret_key) != 1 ||
		fread(&memlimit, sizeof(memlimit), 1, fp_secret_key) != 1 ||
		fread(salt, sizeof(salt), 1, fp_secret_key) != 1 ||
		fread(nonce, sizeof(nonce), 1, fp_secret_key) != 1 ||
		fread(ciphertext, ciphertext_len, 1, fp_secret_key) != 1)
	{
		eprintf("FATAL: Not a nacrypt private key file\n");
		return -1;
	}
	// Stored in network byte-order, convert back to host
	opslimit = ntohl(opslimit);
	memlimit = ntohl(memlimit);

	if (opslimit == 0) {
		eprintf("FATAL: Invalid opslimit in private key file\n");
		return -1;
	}

	if (memlimit == 0) {
		eprintf("FATAL: Invalid memlimit in private key file\n");
		return -1;
	}

	unsigned char* box_key = sodium_malloc(crypto_secretbox_KEYBYTES);
	if (box_key == NULL) {
		perror("FATAL: sodium_malloc()");
		return -1;
	}

	if (derive_key(box_key, crypto_secretbox_KEYBYTES, salt, password,
				   (unsigned long long)opslimit, (size_t)memlimit) != 0)
	{
		eprintf("FATAL: Failed to derive key\n");
		safe_sodium_free(box_key);
		return -1;
	}

	if (crypto_secretbox_open_easy(secret_key_buf, ciphertext, ciphertext_len,
								   nonce, box_key) != 0)
	{
		eprintf("FATAL: Incorrect password or corrupted private key file\n");
		safe_sodium_free(box_key);
		return -1;
	}

	safe_sodium_free(box_key);
	return 0;
}

int encrypt_file_symmetric(FILE* input_file, FILE* output_file,
						   const char* const password) {
	if (input_file == NULL || output_file == NULL || password == NULL)
		return -1;
	const unsigned char SYMMETRY_BYTE = SYMMETRY_SYMMETRIC;
	const uint32_t opslimit = NACRYPT_OPSLIMIT_DEFAULT;
	const uint32_t memlimit = NACRYPT_MEMLIMIT_DEFAULT;
	const uint32_t net_opslimit = htonl(opslimit);
	const uint32_t net_memlimit = htonl(memlimit);
	unsigned char salt[SALT_LEN];

	unsigned char* key = sodium_malloc(KEY_LEN);
	if (key == NULL) {
		perror("FATAL: sodium_malloc()");
		return -1;
	}

	randombytes_buf(salt, sizeof salt);

	if (derive_key(key, KEY_LEN, salt, password, opslimit, memlimit) != 0) {
		eprintf("FATAL: Failed to derive key: Out of memory\n");
		goto error;
	}

	// Write header info
	if (fwrite(NACRYPT_MAGIC, sizeof(NACRYPT_MAGIC), 1, output_file) != 1 ||
		fwrite(&HEADER_VERSION_BYTE, 1, 1, output_file) != 1 ||
		fwrite(&SYMMETRY_BYTE, 1, 1, output_file) != 1 ||
		fwrite(&net_opslimit, sizeof(net_opslimit), 1, output_file) != 1 ||
		fwrite(&net_memlimit, sizeof(net_memlimit), 1, output_file) != 1 ||
		fwrite(salt, 1, sizeof(salt), output_file) != SALT_LEN)
	{
		perror("FATAL: fwrite");
		goto error;
	}

	// Write the actual ciphertext
	int ret = encrypt_file(input_file, output_file, key);
	safe_sodium_free(key);
	return ret;

error:
	safe_sodium_free(key);
	return -1;
}

int encrypt_file_asymmetric(
	FILE* input_file, FILE* output_file, unsigned char num_recipients,
	unsigned char recipient_pubkeys[num_recipients]
								   [crypto_box_PUBLICKEYBYTES]) {
	if (input_file == NULL || output_file == NULL ||
		num_recipients > MAX_NUM_RECIPIENTS || num_recipients == 0)
		return -1;

	const unsigned char SYMMETRY_BYTE = SYMMETRY_ASYMMETRIC;
	const unsigned char num_recipients_byte = num_recipients;
	unsigned char* key = sodium_malloc(KEY_LEN);
	if (key == NULL) {
		perror("FATAL: sodium_malloc()");
		return -1;
	}

	// Generate a new key to be sealed inside boxes for the recipients later
	crypto_secretstream_xchacha20poly1305_keygen(key);
	const size_t box_len =
		crypto_box_SEALBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES;
	unsigned char sealed_box[box_len];

	// Write header info
	if (fwrite(NACRYPT_MAGIC, sizeof(NACRYPT_MAGIC), 1, output_file) != 1 ||
		fwrite(&HEADER_VERSION_BYTE, 1, 1, output_file) != 1 ||
		fwrite(&SYMMETRY_BYTE, 1, 1, output_file) != 1 ||
		fwrite(&num_recipients_byte, 1, 1, output_file) != 1)
	{
		perror("fwrite");
		goto error;
	}

	for (unsigned char i = 0; i < num_recipients; i++) {
		if (crypto_box_seal(sealed_box, key,
							crypto_secretstream_xchacha20poly1305_KEYBYTES,
							recipient_pubkeys[i]) != 0)
		{
			// Shouldn't happen
			eprintf("FATAL: crypto_box_seal() failed\n");
			goto error;
		}

		// Write the box
		if (fwrite(sealed_box, box_len, 1, output_file) != 1) {
			perror("FATAL: fwrite");
			goto error;
		}
	}

	// Write the actual ciphertext
	int ret = encrypt_file(input_file, output_file, key);
	safe_sodium_free(key);
	return ret;

error:
	safe_sodium_free(key);
	return -1;
}

int encrypt_file(FILE* input_file, FILE* output_file,
				 const unsigned char* const key) {
	if (input_file == NULL || output_file == NULL || key == NULL)
		return -1;
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

	// buf_in and buf_out likely wont be locked because of lock limit, but it
	// doesnt matter that much
	buf_in = (unsigned char*)sodium_malloc(BUF_IN_LEN);
	if (buf_in == NULL) {
		perror("FATAL: sodium_malloc()");
		return -1;
	}

	buf_out = (unsigned char*)sodium_malloc(BUF_OUT_LEN);
	if (buf_out == NULL) {
		perror("FATAL: sodium_malloc()");
		safe_sodium_free(buf_in);
		return -1;
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

	safe_sodium_free(buf_in);
	safe_sodium_free(buf_out);
	return 0;

error:
	safe_sodium_free(buf_in);
	safe_sodium_free(buf_out);
	return -1;
}

int decrypt_file_symmetric(FILE* input_file, FILE* output_file,
						   const char* const password) {
	if (input_file == NULL || output_file == NULL || password == NULL)
		return -1;
	// This function assumes the file offset is currently directly after
	// SYMMETRY_BYTE
	uint32_t opslimit;
	uint32_t memlimit;
	unsigned char salt[SALT_LEN];

	if (fread(&opslimit, sizeof(opslimit), 1, input_file) != 1 ||
		fread(&memlimit, sizeof(memlimit), 1, input_file) != 1 ||
		fread(salt, sizeof(salt), 1, input_file) != 1)
	{
		eprintf("FATAL: Not a nacrypt file\n");
		return -1;
	}

	// Stored in network byte-order, convert back to host
	opslimit = ntohl(opslimit);
	memlimit = ntohl(memlimit);

	if (opslimit == 0) {
		eprintf("FATAL: Invalid opslimit in header\n");
		return -1;
	}

	if (memlimit == 0) {
		eprintf("FATAL: Invalid memlimit in header\n");
		return -1;
	}

	unsigned char* key = sodium_malloc(KEY_LEN);
	if (key == NULL) {
		perror("FATAL: sodium_malloc()");
		return -1;
	}

	if (derive_key(key, KEY_LEN, salt, password, opslimit, memlimit) != 0) {
		eprintf("FATAL: Failed to derive key: Out of memory\n");
		goto error;
	}

	int ret = decrypt_file(input_file, output_file, key);
	safe_sodium_free(key);
	return ret;

error:
	safe_sodium_free(key);
	return -1;
}

int decrypt_file_asymmetric(FILE* input_file, FILE* output_file,
							const unsigned char* const secret_key) {
	if (input_file == NULL || output_file == NULL || secret_key == NULL)
		return -1;
	// This function assumes the file offset is currently directly after
	// SYMMETRY_BYTE
	unsigned char num_recipients_byte;
	if (fread(&num_recipients_byte, 1, 1, input_file) != 1) {
		eprintf("FATAL: Failed to read number of recipients\n");
		return -1;
	}

	if (num_recipients_byte == 0) {
		eprintf(
			"FATAL: Failed to read number of recipients, cannot be zero!\n");
	}

	if (num_recipients_byte > MAX_NUM_RECIPIENTS) {
		eprintf("FATAL: Too many recipients in file\n");
		return -1;
	}

	// Get the public key back from the private key, needed to open the box
	unsigned char public_key[crypto_box_PUBLICKEYBYTES];
	crypto_scalarmult_base(public_key, secret_key);

	const size_t box_len =
		crypto_box_SEALBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES;
	unsigned char sealed_box[box_len];

	unsigned char* key = sodium_malloc(KEY_LEN);
	if (key == NULL) {
		perror("FATAL: sodium_malloc()");
		return -1;
	}

	// Go over each box and see if the box was intended for us
	int found_good_box = 0;
	for (unsigned char i = 0; i < num_recipients_byte; i++) {
		if (fread(sealed_box, box_len, 1, input_file) != 1) {
			eprintf("FATAL: Failed to read sealed box\n");
			goto error;
		}

		if (found_good_box == 1) {
			// If we already found the good box in a previous iteration then
			// just go to next iteration (because we still need to fread all the
			// other boxes up until the start of ciphertext)
			continue;
		}

		if (crypto_box_seal_open(key, sealed_box, box_len, public_key,
								 secret_key) == 0)
		{
			// This box was intended for us and has been unsealed.
			found_good_box = 1;
		}
		// Box was not for us, try next
	}

	if (found_good_box != 1) {
		eprintf("FATAL: No sealed boxes were openable in this file, either "
				"corrupted file or you are not a recipient\n");
		goto error;
	}

	int ret = decrypt_file(input_file, output_file, key);
	safe_sodium_free(key);
	return ret;

error:
	safe_sodium_free(key);
	return -1;
}

int decrypt_file(FILE* input_file, FILE* output_file,
				 const unsigned char* const key) {
	if (input_file == NULL || output_file == NULL || key == NULL)
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

	// buf_in and buf_out likely wont be locked because of lock limit, but it
	// doesnt matter that much
	buf_out = (unsigned char*)sodium_malloc(BUF_OUT_LEN);
	if (buf_out == NULL) {
		perror("FATAL: sodium_malloc");
		return -1;
	}

	buf_in = (unsigned char*)sodium_malloc(BUF_IN_LEN);
	if (buf_in == NULL) {
		perror("FATAL: sodium_malloc");
		safe_sodium_free(buf_out);
		return -1;
	}

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

	safe_sodium_free(buf_in);
	safe_sodium_free(buf_out);
	return 0;

error:
	safe_sodium_free(buf_in);
	safe_sodium_free(buf_out);
	return -1;
}
