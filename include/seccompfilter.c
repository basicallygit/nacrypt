#ifndef NO_SECCOMP
#include <seccomp.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include "utils.h"
#endif // !defined(NO_SECCOMP)
#include <stdbool.h>

// Kernel 6.11+ can use MAP_DROPPABLE for mmap vDSO
#ifndef MAP_DROPPABLE
#define MAP_DROPPABLE 0x08
#endif // !defined(MAP_DROPPABLE)


bool apply_seccomp_filter(int input_fd, int output_fd) {
	#ifdef NO_SECCOMP
	return false;
	#else
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		perror("prctl(PR_SET_NO_NEW_PRIVS)");
		return false;
	}

	int fd_whitelist[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, input_fd, output_fd};
	int fd_count = sizeof(fd_whitelist) / sizeof(fd_whitelist[0]);
	
	#ifdef NACRYPT_SECCOMP_DEBUG_TEST
	// Allow testing of seccomp failure without crashes, should not be used outside of tests
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
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);

	if (seccomp_load(ctx) != 0) return false;
	return true;
	#endif
}
