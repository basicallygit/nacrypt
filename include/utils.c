#include "utils.h"
#include <errno.h>
#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

bool file_exists(const char* filename) {
	FILE* file = fopen(filename, "rb");
	if (file) {
		safe_fclose(file);
		return true;
	}
	if (errno == EACCES)
		return true; // File exists but permission was denied
	return false;
}

bool file_is_empty(const char* filename) {
	FILE* file = fopen(filename, "rb");
	if (file == NULL)
		return true;

	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	safe_fclose(file);

	return size == 0;
}

int make_dir(const char* path) {
	if (mkdir(path, 0700) == 0)
		return 0;

	if (errno == EEXIST)
		return 1;

	return -1;
}

char yesno_defaultno_prompt(const char* const prompt) {
	if (ferror(stdin) != 0 || feof(stdin) != 0) {
		eprintf("FATAL: stdin failure\n");
		return 'N';
	}

	char response[10] = {'\0'};

	while (1) {
		if (ferror(stdin) != 0 || feof(stdin) != 0) {
			eprintf("FATAL: stdin failure\n");
			return 'N';
		}

		printf("%s", prompt);
		fflush(stdout);

		if (fgets(response, sizeof(response), stdin) == NULL) {
			perror("FATAL: fgets");
			return 'N';
		}

		if (response[0] == 'y' || response[0] == 'Y')
			return 'Y';
		else if (response[0] == 'n' || response[0] == 'N' ||
				 response[0] == '\n')
		{
			return 'N';
		}
	}
}

// Caller must safe_sodium_free if non-NULL
char* read_password(size_t max_len) {
	if (ferror(stdin) != 0 || feof(stdin) != 0) {
		eprintf("FATAL: stdin failure\n");
		return NULL;
	}

	char* password = (char*)sodium_malloc(max_len);
	if (password == NULL) {
		eprintf("FATAL: sodium_malloc() failed: %s\n", strerror(errno));
		return NULL;
	}

	// Ensure they are all 0x00 so that sodium_memcmp is consistent
	sodium_memzero(password, max_len);

	if (fgets(password, (int)max_len, stdin) != NULL) {
		password[strcspn(password, "\n")] = '\0';
	} else {
		perror("FATAL: fgets");
		sodium_free(password);
		return NULL;
	}

	return password;
}

FILE* fopen_from(const char* const parent_dir, const char* const path,
				 const char* const mode) {
	const size_t full_path_len = strlen(parent_dir) + strlen(path) + 1;
	char* full_path = malloc(full_path_len);
	if (full_path == NULL) {
		return NULL;
	}

	snprintf(full_path, full_path_len, "%s%s", parent_dir, path);

	FILE* fp = fopen(full_path, mode);
	free(full_path);

	return fp;
}

int make_dir_at(const char* const parent_dir, const char* const path) {
	const size_t full_path_len = strlen(parent_dir) + strlen(path) + 1;
	char* full_path = malloc(full_path_len);
	if (full_path == NULL) {
		return -1;
	}

	snprintf(full_path, full_path_len, "%s%s", parent_dir, path);

	int ret = make_dir(full_path);
	free(full_path);

	return ret;
}
