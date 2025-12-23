#include "crypto.h"
#include "seccompfilter.h"
#include "utils.h"
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define MAX_PASSWORD_SIZE 512

void print_usage(FILE *stream) {
	fprintf(stream, "Usage: nacrypt <inputfile> -o <outputfile> [-e|-d]\n\n");
	fprintf(stream, "Options:\n");
	fprintf(
		stream,
		"  -o | --output <filename>: Output to <filename> after processing\n");
	fprintf(stream, "  -e | --encrypt: [optional] speficy encrypt mode\n");
	fprintf(stream, "  -d | --decrypt: [optional] specify decrypt mode\n");
	fflush(stream);
}

enum Mode {
	ENCRYPT,
	DECRYPT,
	UNSPECIFIED,
};

int main(int argc, char **argv) {
	if (argc == 2 &&
		(strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
	{
		print_usage(stdout);
		return 0;
	}
	if (argc < 4 || argc > 5) {
		print_usage(stderr);
		return 1;
	}

	char *input_filename = NULL;
	char *output_filename = NULL;
	enum Mode mode = UNSPECIFIED;

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
		eprintf("FATAL: No output file specified\n");
		return 1;
	}

	// Open input and output files now before entering seccomp restricted mode
	FILE *fp_input = fopen(input_filename, "rb");
	if (fp_input == NULL) {
		eprintf("FATAL: Failed to open %s: %s\n", input_filename,
				strerror(errno));
		return 1;
	}
	FILE *fp_output = fopen(output_filename, "wb");
	if (fp_output == NULL) {
		eprintf("FATAL: Failed to open %s: %s\n", output_filename,
				strerror(errno));
		fclose(fp_input);
		return 1;
	}

#ifndef NO_SECCOMP
	int input_fd = fileno(fp_input);
	int output_fd = fileno(fp_output);

	if (!apply_seccomp_filter(input_fd, output_fd)) {
#ifdef ALLOW_SECCOMP_FAIL
		eprintf("WARNING: Failed to apply seccomp filter.. "
				"(-DALLOW_SECCOMP_FAIL)\n");
#else
		eprintf("FATAL: Failed to apply seccomp filter.. (-DALLOW_SECCOMP_FAIL "
				"not set)\n");
		goto error;
#endif
	}
#endif // !defined(NO_SECCOMP)

	const unsigned char NACRYPT_MAGIC[4] = {0x4E, 0x41, 0x1F, 0xF0};
	unsigned char read_magic_buf[4];
	uint32_t opslimit = NACRYPT_OPSLIMIT_DEFAULT;
	uint32_t memlimit = NACRYPT_MEMLIMIT_DEFAULT;

	switch (mode) {
	case ENCRYPT:
		break;
	case DECRYPT:
		if (fread(&read_magic_buf, 1, 4, fp_input) == 4 &&
			memcmp(NACRYPT_MAGIC, read_magic_buf, 4) == 0 &&
			fread(&opslimit, sizeof(opslimit), 1, fp_input) == 1 &&
			fread(&memlimit, sizeof(memlimit), 1, fp_input) == 1)
		{
			if (opslimit == 0) {
				eprintf("FATAL: %s: Invalid OPSLIMIT in nacrypt header\n",
						input_filename);
				goto error;
			}
			if (memlimit == 0) {
				eprintf("FATAL: %s: Invalid MEMLIMIT in nacrypt header\n",
						input_filename);
				goto error;
			}
			// Valid header, opslimit and memlimit have already been set,
			// nothing to do
		} else {
			eprintf("FATAL: %s: Not a nacrypt file\n", input_filename);
			goto error;
		}

		break;
	case UNSPECIFIED:
		if (fread(&read_magic_buf, 1, 4, fp_input) == 4 &&
			memcmp(NACRYPT_MAGIC, read_magic_buf, 4) == 0 &&
			fread(&opslimit, sizeof(opslimit), 1, fp_input) == 1 &&
			fread(&memlimit, sizeof(memlimit), 1, fp_input) == 1)
		{
			if (opslimit == 0) {
				eprintf("WARNING: %s: Contains nacrypt header but OPSLIMIT is "
						"invalid, treating as encrypt..\n",
						input_filename);
				opslimit = NACRYPT_OPSLIMIT_DEFAULT;
				memlimit = NACRYPT_MEMLIMIT_DEFAULT;
				rewind(fp_input); // Go back to the start
				mode = ENCRYPT;
				break;
			}
			if (memlimit == 0) {
				eprintf("WARNING: %s: Contains nacrypt header but MEMLIMIT is "
						"invalid, treating as encrypt..\n",
						input_filename);
				opslimit = NACRYPT_OPSLIMIT_DEFAULT;
				memlimit = NACRYPT_MEMLIMIT_DEFAULT;
				rewind(fp_input); // Go back to the start
				mode = ENCRYPT;
				break;
			}
			// We have a valid nacrypt header
			mode = DECRYPT;
		} else {
			rewind(fp_input); // Go back to the start
			mode = ENCRYPT;
		}
		break;
	default:
		eprintf("FATAL: Invalid mode\n");
		goto error;
	}

	// Ask for password
	if (mode == ENCRYPT)
		printf("Please create a password: ");
	else
		printf("Please enter password: ");
	fflush(stdout);

	char password[MAX_PASSWORD_SIZE];
	if (fgets(password, sizeof(password), stdin) != NULL) {
		password[strcspn(password, "\n")] = '\0';
	} else {
		perror("FATAL: fgets");
		goto error;
	}

	if (mode == ENCRYPT) {
		printf("Please re-enter the password: ");
		fflush(stdout);
		char password_two[MAX_PASSWORD_SIZE];
		if (fgets(password_two, sizeof(password_two), stdin) != NULL) {
			password_two[strcspn(password_two, "\n")] = '\0';
		} else {
			perror("FATAL: fgets");
			goto error;
		}
		if (strncmp(password, password_two, MAX_PASSWORD_SIZE) != 0) {
			eprintf("Passwords did not match.\n");
			goto error;
		}
	}

	if (mode == ENCRYPT) {
		if (fwrite(NACRYPT_MAGIC, 1, 4, fp_output) != 4 ||
			fwrite(&opslimit, sizeof(opslimit), 1, fp_output) != 1 ||
			fwrite(&memlimit, sizeof(memlimit), 1, fp_output) != 1)
		{
			perror("FATAL: fwrite");
			goto error;
		}
		if (!encrypt_file(fp_input, fp_output, password,
						  (unsigned long long)opslimit, (size_t)memlimit))
			goto error;
	} else {
		if (!decrypt_file(fp_input, fp_output, password,
						  (unsigned long long)opslimit, (size_t)memlimit))
			goto error;
	}

	fclose(fp_input);
	fclose(fp_output);
	return 0;

error:
	fclose(fp_input);
	fclose(fp_output);
	return 1;
}
