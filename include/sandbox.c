#ifndef NO_SANDBOX
#include "utils.h"
#include <fcntl.h>
#include <unistd.h>

#if defined(__linux__)
#include <seccomp.h>
#include <sys/mman.h>
#include <sys/prctl.h>
// Kernel 6.11+ can use MAP_DROPPABLE for mmap vDSO
#ifndef MAP_DROPPABLE
#define MAP_DROPPABLE 0x08
#endif // !defined(MAP_DROPPABLE)
#endif // defined(__linux__)

#endif // !defined(NO_SANDBOX)

#include <stdbool.h>

bool apply_sandbox(int input_fd, int output_fd) {
#ifdef NO_SANDBOX
	return false;
#else
#if defined(__linux__)
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		perror("prctl(PR_SET_NO_NEW_PRIVS)");
		return false;
	}

	int fd_whitelist[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, input_fd,
						  output_fd};
	int fd_count = sizeof(fd_whitelist) / sizeof(fd_whitelist[0]);

#ifdef NACRYPT_SECCOMP_DEBUG_TEST
	// Allow testing of seccomp failure without crashes, should not be used
	// outside of tests
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);
#else
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
#endif

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	for (int i = 0; i < fd_count; i++) {
		// read
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1,
						 SCMP_A0(SCMP_CMP_EQ, fd_whitelist[i]));
		// write
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
						 SCMP_A0(SCMP_CMP_EQ, fd_whitelist[i]));
		// lseek
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 1,
						 SCMP_A0(SCMP_CMP_EQ, fd_whitelist[i]));
		// fstat
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1,
						 SCMP_A0(SCMP_CMP_EQ, fd_whitelist[i]));
		// close
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 1,
						 SCMP_A0(SCMP_CMP_EQ, fd_whitelist[i]));
	}
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

	// Block mmap PROT_EXEC
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 1,
					 SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, 0));
	// Allow mmap MAP_ANONYMOUS | MAP_PRIVATE
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 1,
					 SCMP_A3(SCMP_CMP_MASKED_EQ, MAP_ANONYMOUS | MAP_PRIVATE,
							 MAP_ANONYMOUS | MAP_PRIVATE));
	// Allow mmap MAP_DROPPABLE | MAP_PRIVATE
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 1,
					 SCMP_A3(SCMP_CMP_MASKED_EQ, MAP_DROPPABLE | MAP_PRIVATE,
							 MAP_DROPPABLE | MAP_PRIVATE));

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 1,
					 SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, 0));
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);

	// Safe fcntl args
	// fnctl F_GETFD || F_SETFD
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 1,
					 SCMP_A1(SCMP_CMP_EQ, F_GETFD));
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 1,
					 SCMP_A1(SCMP_CMP_EQ, F_SETFD));
	// fnctl F_GETFL || F_SETFL
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 1,
					 SCMP_A1(SCMP_CMP_EQ, F_GETFL));
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 1,
					 SCMP_A1(SCMP_CMP_EQ, F_SETFL));
	// fnctl F_DUPFD || F_DUPFD_CLOEXEC
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 1,
					 SCMP_A1(SCMP_CMP_EQ, F_DUPFD));
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 1,
					 SCMP_A1(SCMP_CMP_EQ, F_DUPFD_CLOEXEC));

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);

	int ret = seccomp_load(ctx);
	seccomp_release(ctx);

	return ret == 0;
#elif defined(__OpenBSD__)
	// Pledge "stdio" which only allows basic file operations on already open
	// files and other required process syscalls
	if (pledge("stdio", NULL) != 0) {
		perror("pledge");
		return false;
	}
	return true;
#else
	return false; // Fallback return value on non-supported OS
#endif // defined(__linux__) | defined(__OpenBSD__)
#endif // NO_SANDBOX
}
