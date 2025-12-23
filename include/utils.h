#ifndef NACRYPT_UTILS_H
#define NACRYPT_UTILS_H

#include <stdbool.h>
#include <stdio.h>

#define eprintf(...)                                                           \
	do {                                                                       \
		fprintf(stderr, __VA_ARGS__);                                          \
		fflush(stderr);                                                        \
	} while (0)

bool file_exists(const char *filename);
bool file_is_empty(const char *filename);

#endif // !defined(NACRYPT_UTILS_H)
