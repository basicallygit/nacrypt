#ifndef NACRYPT_UTILS_H
#define NACRYPT_UTILS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define eprintf(...)                                                           \
	do {                                                                       \
		fprintf(stderr, __VA_ARGS__);                                          \
		fflush(stderr);                                                        \
	} while (0)

bool file_exists(const char* filename);
bool file_is_empty(const char* filename);
int make_dir(const char* path);
char* read_password(size_t max_len);

FILE* fopen_from(const char* const parent_dir, const char* const path,
				 const char* const mode);

int make_dir_at(const char* const parent_dir, const char* const path);

#endif // !defined(NACRYPT_UTILS_H)
