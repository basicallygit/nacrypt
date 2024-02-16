#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include "include/utils.h"
#include "include/crypto.h"

#define MAX_PASSWD_SIZE 256

void print_usage(FILE* stream) {
	fprintf(stream, "Usage:\n");
	fprintf(stream, "  nacrypt <input_file> -o <output_file> [-e|-d]\n\n");

	fprintf(stream, "Flags:\n");
	fprintf(stream, "  -o  <output_file>  Write the resulting data to <output_file>\n");
	fprintf(stream, "  -e, --encrypt      Set the mode to encryption\n");
	fprintf(stream, "  -d, --decrypt      Set the mode to decryption\n");
	fflush(stream);
}

enum Mode {
	Encrypt,
	Decrypt,
};

int main(int argc, char** argv) {
	char* input_file;
	char* output_file;
	char password[MAX_PASSWD_SIZE];
	enum Mode mode;

	// Handle arguments
	if (argc == 2) {
		if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
			print_usage(stdout);
			return 0;
		}
		print_usage(stderr);
		return 1;
	}
	else if (argc == 5) {
		if (strcmp(argv[1], "-o") == 0 || strcmp(argv[1], "--output") == 0) {
			output_file = argv[2];
			input_file = argv[3];
		}
		else if (strcmp(argv[2], "-o") == 0 || strcmp(argv[1], "--output") == 0) {
			output_file = argv[3];
			input_file = argv[1];
		}
		else {
			print_usage(stderr);
			return 1;
		}

		if (strcmp(argv[4], "-e") == 0 || strcmp(argv[4], "--encrypt") == 0) {
			mode = Encrypt;
		}
		else if (strcmp(argv[4], "-d") == 0 || strcmp(argv[4], "--decrypt") == 0) {
			mode = Decrypt;
		}
		else {
			print_usage(stderr);
			return 1;
		}
	}
	else {
		print_usage(stderr);
		return 1;
	}
	
	// Check if the input file exists
	if (!file_exists(input_file)) {
		fprintf(stderr, "%s: No such file or directory\n", input_file);
		fflush(stderr);
		return 1;
	}

	// Check if the output file already exists
	if (file_exists(output_file)) {
		fprintf(stderr, "%s: File already exists\n", output_file);
		fflush(stderr);
		return 1;
	}
	

	// Initialize sodium
	if (sodium_init() != 0) {
		fprintf(stderr, "Failed to initialize libsodium, exiting..\n");
		fflush(stderr);
		return 1;
	}
	
	if (mode == Encrypt)
		printf("Please create a password: ");
	else 
		printf("Please enter the password for %s: ", input_file);
	fflush(stdout);

	// Ask for the password to use
	if (fgets(password, MAX_PASSWD_SIZE - 1, stdin) == NULL) {
		fprintf(stderr, "Failed to read the password.\n");
		fflush(stderr);
		return 1;
	}

	if (mode == Encrypt) {
		encrypt_file(input_file, output_file, password);
	}
	else { // Decrypt
		decrypt_file(input_file, output_file, password);
	}

	return 0;
}

