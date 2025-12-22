#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include "utils.h"

bool file_exists(const char* filename) {
	FILE* file = fopen(filename, "rb");
	if (file) {
		fclose(file);
		return true;
	}
	if (errno == EACCES) return true; // File exists but permission was denied opening
	return false;
}

bool file_is_empty(const char* filename) {
	FILE* file = fopen(filename, "rb");
	if (file == NULL) return true;

	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	fclose(file);

	return size == 0;
}

