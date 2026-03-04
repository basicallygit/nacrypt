#include "crypto.h"
#include "sandbox.h"
#include "utils.h"
#include "version.h"
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NACRYPT_HELP_MESSAGE                                                   \
	"Usage: nacrypt <inputfile> -o <outputfile> [-e,-d,-r,-p,-vv]\n\n"         \
	"Options:\n"                                                               \
	"  -h, --help                Display this help message\n"                  \
	"  -o, --output <filename>   Output to <filename>\n"                       \
	"  -e, --encrypt [optional]  Specify encrypt mode\n"                       \
	"  -d, --decrypt [optional]  Specify decrypt mode\n"                       \
	"  -g, --gen-key             Generate a new keypair\n"                     \
	"  -R, --regen-public        Regenerate your public key if its lost\n"     \
	"  -r, --recipient <pubkey>  Encrypt this file to <pubkey>\n"              \
	"  -p, --private-key <path>  Specify custom path to private key\n"         \
	"  -v, --version             Print nacrypt version info\n"                 \
	"  -vv, --verbose            Print verbose output\n"

void print_usage(FILE* stream) {
	fprintf(stream, NACRYPT_HELP_MESSAGE);
	fflush(stream);
}

enum Mode {
	ENCRYPT,
	DECRYPT,
	UNSPECIFIED,
};

int main(int argc, char** argv) {
	// Stop musl libc from using ioctl
	setvbuf(stdout, NULL, _IOLBF, BUFSIZ);

	// Make sure no NULL arguments
	for (int x = 0; x < argc; x++) {
		if (argv[x] == NULL) {
			eprintf("FATAL: NULL argument\n");
			return 1;
		}
	}

	if (argc == 2) {
		if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
			print_usage(stdout);
			return 0;
		} else if (strcmp(argv[1], "-g") == 0 ||
				   strcmp(argv[1], "--gen-key") == 0)
		{
			if (sodium_init() != 0) {
				eprintf("FATAL: sodium_init() failed\n");
				return 1;
			}

			if (generate_keypair() != 0)
				return 1;
			return 0;
		} else if (strcmp(argv[1], "-R") == 0 ||
				   strcmp(argv[1], "--regen-public") == 0)
		{
			if (sodium_init() != 0) {
				eprintf("FATAL: sodium_init() failed\n");
				return 1;
			}

			if (regenerate_public_key() != 0)
				return 1;
			return 0;
		} else if (strcmp(argv[1], "-v") == 0 ||
				   strcmp(argv[1], "--version") == 0)
		{
			printf("Nacrypt version %s\nCopyright (C) 2026 basicallygit "
				   "(Apache-2.0 License)\n",
				   NACRYPT_VERSION);
			return 0;
		}
	}

	// nacrypt, input.txt, -o, output.txt [--{en,de}crypt] + MAX_NUM_RECIPIENTS
	// * 2 for the -r before each one
	const int max_argc = 5 + (MAX_NUM_RECIPIENTS * 2);
	if (argc < 4 || argc > max_argc) {
		print_usage(stderr);
		return 1;
	}

	char* input_filename = NULL;
	char* output_filename = NULL;
	unsigned char num_recipients = 0;
	char* recipient_pubkeys_armored[MAX_NUM_RECIPIENTS];
	char* custom_secret_key_path = NULL;
	enum Mode mode = UNSPECIFIED;
	int verbose = 0;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
			if (i == argc - 1) { // No more arguments
				eprintf("FATAL: No filename provided after %s\n", argv[i]);
				return 1;
			}
			output_filename = argv[i + 1];
			i++; // Skip over output file
		} else if (strcmp(argv[i], "-e") == 0 ||
				   strcmp(argv[i], "--encrypt") == 0)
		{
			mode = ENCRYPT;
		} else if (strcmp(argv[i], "-d") == 0 ||
				   strcmp(argv[i], "--decrypt") == 0)
		{
			mode = DECRYPT;
		} else if (strcmp(argv[i], "-r") == 0 ||
				   strcmp(argv[i], "--recipient") == 0)
		{
			if (i == argc - 1) {
				eprintf("FATAL: No public key given after %s\n", argv[i]);
				return -1;
			}

			if (num_recipients == MAX_NUM_RECIPIENTS) {
				eprintf("FATAL: Too many recipients (max %d)\n",
						MAX_NUM_RECIPIENTS);
				return -1;
			}

			recipient_pubkeys_armored[num_recipients] = argv[i + 1];
			num_recipients++;
			i++;
		} else if (strcmp(argv[i], "-p") == 0 ||
				   strcmp(argv[i], "--private-key") == 0)
		{
			if (i == argc - 1) {
				eprintf("FATAL: No path given after %s\n", argv[i]);
				return -1;
			}
			custom_secret_key_path = argv[i + 1];
			i++;
		} else if (strcmp(argv[i], "-vv") == 0 ||
				   strcmp(argv[i], "--verbose") == 0)
		{
			verbose = 1;
		} else if (argv[i][0] == '-') {
			eprintf("FATAL: Unknown argument: %s\n", argv[i]);
			return 1;
		} else {
			if (input_filename != NULL) {
				eprintf("FATAL: more than one input files specified: %s, %s\n",
						input_filename, argv[i]);
				return 1;
			}
			input_filename = argv[i];
		}
	}

	if (input_filename == NULL) {
		eprintf("FATAL: No input file specified\n");
		return 1;
	}

	if (output_filename == NULL) {
		eprintf("FATAL: No input file specified\n");
		return 1;
	}

	FILE* fp_input = fopen(input_filename, "rb");
	if (fp_input == NULL) {
		eprintf("FATAL: Failed to open %s: %s\n", input_filename,
				strerror(errno));
		return 1;
	}

	FILE* fp_output = fopen(output_filename, "wb");
	if (fp_output == NULL) {
		eprintf("FATAL: Failed to open %s: %s\n", output_filename,
				strerror(errno));
		safe_fclose(fp_input);
		return 1;
	}

	// Open the private key file now even if not needed, as fopen() will be
	// blocked once sandboxed. Note that this will deliberately be left open
	// until the end, to prevent its file descriptor being reclaimed
	FILE* fp_secret_key = NULL;
	const char* homedir = getenv("HOME");
	if (custom_secret_key_path != NULL) {
		fp_secret_key = fopen(custom_secret_key_path, "rb");
	} else {
		if (homedir != NULL) {
			fp_secret_key = fopen_from(homedir, SECRET_KEY_PATH, "rb");
		}
	}

#if !defined(NO_SANDBOX)
	int input_fd = fileno(fp_input);
	int output_fd = fileno(fp_output);
	int secret_key_fd = -1; // Will be skipped over unless fopen succeeded
	if (fp_secret_key != NULL)
		secret_key_fd = fileno(fp_secret_key);

	if (verbose == 1) {
		puts("[VERBOSE] Applying sandbox..");
	}
	if (apply_sandbox(input_fd, output_fd, secret_key_fd) != 0) {
#if defined(ALLOW_SANDBOX_FAIL)
		eprintf("WARNING: Failed to apply sandbox.. (non-fatal because of "
				"-DALLOW_SANDBOX_FAIL)\n");
		if (yesno_defaultno_prompt(
				"Would you like to continue unsandboxed [y/N]: ") != 'Y')
		{
			eprintf("Aborting..\n");
			goto error;
		}
#else
		eprintf("FATAL: Failed to apply sandbox.. (-DALLOW_SANDBOX_FAIL not "
				"set)\n");
		goto error;
#endif // defined(ALLOW_SANDBOX_FAIL) || !defined(ALLOW_SANDBOX_FAIL)
	}
#endif // !defined(NO_SANDBOX)
	if (verbose == 1)
		puts("[VERBOSE] Applied sandbox successfully");

	// Since this is now sandboxed, opening /dev/(u)random wont work.
	// libsodium must use the getrandom() syscall, so this requires kernel 3.17+
	if (sodium_init() != 0) {
		eprintf("FATAL: sodium_init() failed\n");
		goto error;
	}

	int symmetry = 99; // Dummy value

	if (mode == DECRYPT || mode == UNSPECIFIED) {
		// Check if the input file is a nacrypt file. If it isnt, assume user
		// wants to decrypt it UNLESS --decrypt was explicitly given, in which
		// case bail out
		unsigned char magic_buf[4];
		unsigned char header_version_byte;
		unsigned char symmetry_byte;
		if (fread(magic_buf, sizeof(magic_buf), 1, fp_input) != 1 ||
			memcmp(magic_buf, NACRYPT_MAGIC, sizeof(magic_buf)) != 0 ||
			fread(&header_version_byte, 1, 1, fp_input) != 1 ||
			fread(&symmetry_byte, 1, 1, fp_input) != 1)
		{
			// Incomplete read
			if (mode == UNSPECIFIED) {
				// Not valid, assume user wants to encrypt
				rewind(fp_input);
				mode = ENCRYPT;
			} else {
				eprintf("FATAL: %s: Not a nacrypt file\n", input_filename);
				goto error;
			}
		} else {
			// Valid header
			mode = DECRYPT;
			if (header_version_byte != 1) {
				eprintf("FATAL: %s: Unknown nacrypt format version, possibly "
						"outdated program?\n",
						input_filename);
				goto error;
			}

			if (symmetry_byte != SYMMETRY_SYMMETRIC &&
				symmetry_byte != SYMMETRY_ASYMMETRIC)
			{
				eprintf(
					"FATAL: %s: Invalid symmetry byte: %02x, expected %02x\n",
					input_filename, symmetry_byte, SYMMETRY_SYMMETRIC);
				goto error;
			}

			symmetry = symmetry_byte;
		}
	}

	if (mode == ENCRYPT) {
		if (num_recipients != 0) {
			// Public keys were provided, asymmetric encrypt mode
			unsigned char recipient_public_keys[MAX_NUM_RECIPIENTS]
											   [crypto_box_PUBLICKEYBYTES];
			for (unsigned char j = 0; j < num_recipients; j++) {
				if (dearmor_public_key(recipient_pubkeys_armored[j],
									   recipient_public_keys[j]) != 0)
				{
					eprintf("FATAL: %s: Not a valid nacrypt public key\n",
							recipient_pubkeys_armored[j]);
					goto error;
				}
			}

			if (encrypt_file_asymmetric(fp_input, fp_output, num_recipients,
										recipient_public_keys) != 0)
			{
				eprintf("FATAL: Failed to encrypt file\n");
				goto error;
			}
		} else {
			// Symmetric encrypt mode
			printf("Please create a password: ");
			fflush(stdout);

			char* password = read_password(MAX_PASSWORD_SIZE);
			if (password == NULL) {
				goto error;
			}

			printf("Enter password again: ");
			fflush(stdout);

			char* password_again = read_password(MAX_PASSWORD_SIZE);
			if (password_again == NULL) {
				safe_sodium_free(password);
				goto error;
			}

			if (sodium_memcmp(password, password_again, MAX_PASSWORD_SIZE) != 0)
			{
				eprintf("FATAL: Passwords did not match\n");
				safe_sodium_free(password);
				safe_sodium_free(password_again);
				goto error;
			}

			safe_sodium_free(password_again);

			if (encrypt_file_symmetric(fp_input, fp_output, password) != 0) {
				eprintf("FATAL: Failed to encrypt file\n");
				safe_sodium_free(password);
				goto error;
			}

			safe_sodium_free(password);
		}
	} else if (mode == DECRYPT) {
		if (symmetry == SYMMETRY_ASYMMETRIC) {
			// Asymmetric decrypt

			// Secret key couldn't be opened or couldn't get $HOME
			if (fp_secret_key == NULL) {
				if (custom_secret_key_path != NULL) {
					eprintf("FATAL: Failed to open %s\n",
							custom_secret_key_path);
				} else {
					if (homedir == NULL) {
						eprintf(
							"FATAL: Failed to get home directory from $HOME\n");
					} else {
						eprintf("FATAL: Failed to open %s%s\n", homedir,
								SECRET_KEY_PATH);
					}
				}
				goto error;
			}

			if (custom_secret_key_path != NULL) {
				printf("Please enter password for %s: ",
					   custom_secret_key_path);
			} else {
				if (homedir == NULL) {
					eprintf("FATAL: UNREACHABLE\n");
					goto error;
				}
				printf("Please enter password for %s%s: ", homedir,
					   SECRET_KEY_PATH);
			}
			fflush(stdout);

			char* password = read_password(MAX_PASSWORD_SIZE);
			if (password == NULL) {
				goto error;
			}

			unsigned char* secret_key =
				sodium_malloc(crypto_box_SECRETKEYBYTES);
			if (secret_key == NULL) {
				perror("FATAL: sodium_malloc()");
				sodium_free(password);
				goto error;
			}

			if (read_secret_key(fp_secret_key, secret_key, password) != 0) {
				safe_sodium_free(password);
				safe_sodium_free(secret_key);
				goto error; // Error already printed for us
			}

			safe_sodium_free(password);

			if (decrypt_file_asymmetric(fp_input, fp_output, secret_key) != 0) {
				eprintf("FATAL: Failed to decrypt file\n");
				safe_sodium_free(secret_key);
				goto error;
			}

			safe_sodium_free(secret_key);
		} else {
			// Symmetric decrypt mode
			printf("Password for %s: ", input_filename);
			fflush(stdout);

			char* password = read_password(MAX_PASSWORD_SIZE);
			if (password == NULL) {
				goto error;
			}

			if (decrypt_file_symmetric(fp_input, fp_output, password) != 0) {
				eprintf("FATAL: Failed to decrypt file\n");
				safe_sodium_free(password);
				goto error;
			}

			safe_sodium_free(password);
		}
	} else {
		eprintf("FATAL: UNREACHABLE\n");
		goto error;
	}

	safe_fclose(fp_secret_key);
	safe_fclose(fp_input);
	safe_fclose(fp_output);
	return 0;

error:
	safe_fclose(fp_secret_key);
	safe_fclose(fp_input);
	safe_fclose(fp_output);
	return 1;
}
