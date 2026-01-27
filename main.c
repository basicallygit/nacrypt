#include "crypto.h"
#include "sandbox.h"
#include "utils.h"
#include "version.h"
#include <arpa/inet.h> // htonl, ntohl
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_PASSWORD_SIZE 512

void print_usage(FILE* stream) {
	fprintf(stream,
			"Usage: nacrypt <inputfile> -o <outputfile> [-e,-d,-vv]\n\n");
	fprintf(stream, "Options:\n");
	fprintf(stream, "  -h | --help: Display this help message\n");
	fprintf(stream, "  -o | --output <filename>: Output to <filename>\n");
	fprintf(stream, "  -e | --encrypt: [optional] specify encrypt mode\n");
	fprintf(stream, "  -d | --decrypt: [optional] specify decrypt mode\n");
	fprintf(stream,
			"  -v | --version: [optional] print the nacrypt version info\n");
	fprintf(stream, "  -vv | --verbose: [optional] print verbose output\n");
	fflush(stream);
}

enum Mode {
	ENCRYPT,
	DECRYPT,
	UNSPECIFIED,
};

int main(int argc, char** argv) {
	if (argc == 2) {
		if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
			print_usage(stdout);
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
	if (argc < 4 || argc > 6) {
		print_usage(stderr);
		return 1;
	}

	char* input_filename = NULL;
	char* output_filename = NULL;
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
		fclose(fp_input);
		return 1;
	}

#if !defined(NO_SANDBOX)
	int input_fd = fileno(fp_input);
	int output_fd = fileno(fp_output);

	if (verbose == 1) {
#if defined(TIGHTENED_SANDBOX)
		printf("[VERBOSE] Applying sandbox.. (level: TIGHTENED)\n");
#else
		printf("[VERBOSE] Applying sandbox.. (level: BASIC)\n");
#endif // defined(TIGHTENED_SANDBOX) || !defined(TIGHTENED_SANDBOX)
	}
	if (apply_sandbox(input_fd, output_fd) != 0) {
#if defined(ALLOW_SANDBOX_FAIL)
		eprintf("WARNING: Failed to apply sandbox.. (-DALLOW_SANDBOX_FAIL)\n");
#else
		eprintf("FATAL: Failed to apply sandbox.. (-DALLOW_SANDBOX_FAIL not "
				"set)\n");
		goto error;
#endif // defined(ALLOW_SANDBOX_FAIL)
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

	const unsigned char NACRYPT_MAGIC[4] = {0x4E, 0x41, 0x1F, 0xF0};
	unsigned char magic_buf[4];
	uint32_t opslimit = NACRYPT_OPSLIMIT_DEFAULT;
	uint32_t memlimit = NACRYPT_MEMLIMIT_DEFAULT;

	if (mode != ENCRYPT) { // Attempt to parse header (decrypt or unspecified)
		if (fread(magic_buf, 1, 4, fp_input) == 4 &&
			memcmp(NACRYPT_MAGIC, magic_buf, 4) == 0 &&
			fread(&opslimit, sizeof(opslimit), 1, fp_input) == 1 &&
			fread(&memlimit, sizeof(memlimit), 1, fp_input) == 1)
		{
			// Stored in network order, convert back to host endian
			opslimit = ntohl(opslimit);
			memlimit = ntohl(memlimit);
			if (opslimit == 0) {
				eprintf("FATAL: %s: Invalid OPSLIMIT in header\n",
						input_filename);
				goto error;
			}
			if (memlimit == 0) {
				eprintf("FATAL: %s: Invalid MEMLIMIT in header\n",
						input_filename);
				goto error;
			}
			// Valid header, opslimit and memlimit have already been set,
			// file offset is now at the start of the encrypted data.
			// Set mode to decrypt in-case it was unspecified, as this is a
			// valid nacrypt file to decrypt
			if (verbose == 1)
				printf("[VERBOSE] Found nacrypt header; opslimit: %" PRIu32
					   ", memlimit: %" PRIu32 "\n",
					   opslimit, memlimit);
			mode = DECRYPT;
		} else {
			if (mode == DECRYPT) {
				eprintf("FATAL: %s: Not a nacrypt file\n", input_filename);
				goto error;
			} else {
				if (verbose == 1)
					puts("[VERBOSE] Treating file as encrypt since no valid "
						 "header found");
				// No valid nacrypt header found, treat as ENCRYPT
				mode = ENCRYPT;
				// Go back to the start to make sure the whole file is encrypted
				rewind(fp_input);
			}
		}
	}

	if (mode == ENCRYPT)
		printf("Please create a password: ");
	else
		printf("Please enter password: ");
	fflush(stdout);

	// Sensitive memory, allocate using sodium_malloc for guard pages and no
	// swapping
	char* password = (char*)sodium_malloc(MAX_PASSWORD_SIZE);
	if (password == NULL) {
		eprintf("FATAL: sodium_malloc() failed: %s\n", strerror(errno));
		goto error;
	}

	if (fgets(password, MAX_PASSWORD_SIZE, stdin) != NULL) {
		password[strcspn(password, "\n")] = '\0';
	} else {
		perror("FATAL: fgets");
		sodium_free(password);
		goto error;
	}

	if (mode == ENCRYPT) {
		printf("Enter password again: ");
		fflush(stdout);
		char* password_again = (char*)sodium_malloc(MAX_PASSWORD_SIZE);
		if (password_again == NULL) {
			eprintf("FATAL: sodium_malloc() failed: %s\n", strerror(errno));
			sodium_free(password); // Free the first password because we are
								   // going to quit
			goto error;
		}

		if (fgets(password_again, MAX_PASSWORD_SIZE, stdin) != NULL) {
			password_again[strcspn(password_again, "\n")] = '\0';
		} else {
			perror("FATAL: fgets");
			sodium_free(password);
			sodium_free(password_again);
			goto error;
		}

		if (sodium_memcmp(password, password_again, MAX_PASSWORD_SIZE) != 0) {
			eprintf("FATAL: Passwords didn't match!\n");
			sodium_free(password);
			sodium_free(password_again);
			goto error;
		}
		sodium_free(password_again); // We wont need it again, only temporary
	}

	if (mode == ENCRYPT) {
		opslimit = NACRYPT_OPSLIMIT_DEFAULT;
		memlimit = NACRYPT_MEMLIMIT_DEFAULT;
		// Write bytes in network order
		uint32_t net_opslimit = htonl(opslimit);
		uint32_t net_memlimit = htonl(memlimit);
		if (fwrite(NACRYPT_MAGIC, 1, 4, fp_output) != 4 ||
			fwrite(&net_opslimit, sizeof(net_opslimit), 1, fp_output) != 1 ||
			fwrite(&net_memlimit, sizeof(net_memlimit), 1, fp_output) != 1)
		{
			perror("FATAL: fwrite");
			sodium_free(password);
			goto error;
		}
		if (encrypt_file(fp_input, fp_output, password,
						 (unsigned long long)opslimit, (size_t)memlimit) != 0)
		{
			sodium_free(password);
			goto error;
		}
	} else if (mode == DECRYPT) {
		if (decrypt_file(fp_input, fp_output, password,
						 (unsigned long long)opslimit, (size_t)memlimit) != 0)
		{
			sodium_free(password);
			goto error;
		}
	} else {
		eprintf("FATAL: UNREACHABLE: enum mode was UNSPECIFIED\n");
		sodium_free(password);
		goto error;
	}

	sodium_free(password);
	fclose(fp_input);
	fclose(fp_output);
	return 0;

error:
	fclose(fp_input);
	fclose(fp_output);
	return 1;
}
