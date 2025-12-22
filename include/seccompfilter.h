#ifndef NACRYPT_SECCOMP_FILTER_H
#define NACRYPT_SECCOMP_FILTER_H

#include <stdbool.h>

bool apply_seccomp_filter(int input_fd, int output_fd);

#endif // !defined(SECCOMP_FILTER_H)
