#ifndef NACRYPT_UTILS_H
#define NACRYPT_UTILS_H

#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#define eprintf(...)                                                           \
	do {                                                                       \
		fprintf(stderr, __VA_ARGS__);                                          \
		fflush(stderr);                                                        \
	} while (0)

#define safe_fclose(fp)                                                        \
	do {                                                                       \
		if ((fp) != NULL) {                                                    \
			fclose(fp);                                                        \
			fp = NULL;                                                         \
		} else {                                                               \
			eprintf("FATAL: TRIED TO FCLOSE NULL (this is a bug)\n");          \
			abort();                                                           \
		}                                                                      \
	} while (0)

#define safe_sodium_free(ptr)                                                  \
	do {                                                                       \
		if ((ptr) != NULL) {                                                   \
			sodium_free(ptr);                                                  \
		} else {                                                               \
			eprintf("FATAL: TRIED TO FREE NULL (this is a bug)\n");            \
			abort();                                                           \
		}                                                                      \
	} while (0)

bool file_exists(const char* filename);
bool file_is_empty(const char* filename);
int make_dir(const char* path);
char yesno_defaultno_prompt(const char* const prompt);
char* read_password(size_t max_len);

FILE* fopen_from(const char* const parent_dir, const char* const path,
				 const char* const mode);

int make_dir_at(const char* const parent_dir, const char* const path);

#endif // !defined(NACRYPT_UTILS_H)
