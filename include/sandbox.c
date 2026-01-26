#if !defined(NO_SANDBOX)
#if defined(TIGHTENED_SANDBOX)
#define _GNU_SOURCE
#endif // defined(TIGHTENED_SANDBOX)
#include "utils.h"
#include <fcntl.h>
#include <unistd.h>

#if defined(__linux__)
#include <errno.h>
#include <seccomp.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/prctl.h>

// Kernel 6.11+ can use MAP_DROPPABLE for mmap vDSO
#ifndef MAP_DROPPABLE
#define MAP_DROPPABLE 0x08
#endif
// Bad madvise flags
#ifndef MADV_HWPOISON
#define MADV_HWPOISON 100
#endif
#ifndef MADV_SOFT_OFFLINE
#define MADV_SOFT_OFFLINE 101
#endif

#if defined(TIGHTENED_SANDBOX)
#include <sched.h>
#include <sys/capability.h>
#include <sys/mount.h>
#endif // defined(TIGHTENED_SANDBOX)

#elif defined(__FreeBSD__)
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <termios.h>
#endif // OS checks

#endif // !defined(NO_SANDBOX)

int apply_sandbox(int input_fd, int output_fd) {
#if defined(NO_SANDBOX)
	return -1;
#else // !defined(NO_SANDBOX)
#if defined(__linux__)
#if defined(TIGHTENED_SANDBOX)
	if (unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID |
				CLONE_NEWUTS) != 0)
	{
		perror("unshare");
		return -1;
	}

	// Chroot into safe directory
	const char* jail = "/proc/self/fdinfo";
	if (chdir(jail) != 0 || chroot(jail) != 0) {
		perror("chdir/chroot");
		return -1;
	}
	if (chdir("/") != 0) {
		perror("chdir");
		return -1;
	}

	// Prevent gaining of new privileges
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		perror("prctl(PR_SET_NO_NEW_PRIVS)");
		return -1;
	}

	// Drop capabilities from the bounding set
	for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0) {
			// Some capabilities might not be supported by kernel
			continue;
		}
	}

	// Drop effective/inheritable/permitted caps
	cap_t caps = cap_get_proc();
	if (caps == NULL)
		return -1;
	if (cap_clear(caps) != 0) {
		cap_free(caps);
		return -1;
	}
	if (cap_set_proc(caps) != 0) {
		cap_free(caps);
		return -1;
	}
	cap_free(caps);
#else  // !defined(TIGHTENED_SANDBOX)
	// Only prevent gaining new privileges
	// Required for seccomp
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		perror("prctl(PR_SET_NO_NEW_PRIVS)");
		return -1;
	}
#endif // defined(TIGHTENED_SANDBOX) || !defined(TIGHTENED_SANDBOX)
	// NO_NEW_PRIVS is now set either way, apply seccomp

	int fd_whitelist[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, input_fd,
						  output_fd};
	int fd_count = sizeof(fd_whitelist) / sizeof(fd_whitelist[0]);

#if defined(NACRYPT_SECCOMP_DEBUG)
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);
#else
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
#endif // NACRYPT_SECCOMP_DEBUG
	if (ctx == NULL)
		return -1;
#define ALLOW_RULE(ctx, syscall, ...)                                          \
	do {                                                                       \
		if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(syscall),           \
							 __VA_ARGS__) < 0)                                 \
		{                                                                      \
			goto error;                                                        \
		}                                                                      \
	} while (0)
	ALLOW_RULE(ctx, exit_group, 0);
	ALLOW_RULE(ctx, exit, 0);
	ALLOW_RULE(ctx, brk, 0);
	ALLOW_RULE(ctx, munmap, 0);
	ALLOW_RULE(ctx, getrandom, 0);
	ALLOW_RULE(ctx, dup, 0);
	ALLOW_RULE(ctx, rt_sigprocmask, 0);
	ALLOW_RULE(ctx, rt_sigreturn, 0);
	ALLOW_RULE(ctx, mlock, 0);
	ALLOW_RULE(ctx, munlock, 0);
	ALLOW_RULE(ctx, madvise, 1, SCMP_A2(SCMP_CMP_EQ, MADV_DODUMP));
	ALLOW_RULE(
		ctx, madvise, 1,
		SCMP_A2(SCMP_CMP_MASKED_EQ, MADV_SOFT_OFFLINE | MADV_HWPOISON, 0));
	for (int i = 0; i < fd_count; i++) {
		// read
		ALLOW_RULE(ctx, read, 1,
				   SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)fd_whitelist[i]));
		// write
		ALLOW_RULE(ctx, write, 1,
				   SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)fd_whitelist[i]));
		// lseek
		ALLOW_RULE(ctx, lseek, 1,
				   SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)fd_whitelist[i]));
		// fstat
		ALLOW_RULE(ctx, fstat, 1,
				   SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)fd_whitelist[i]));
		// close
		ALLOW_RULE(ctx, close, 1,
				   SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)fd_whitelist[i]));
	}
	// Block mmap PROT_EXEC, MAP_SHARED and MAP_GROWSDOWN
	ALLOW_RULE(ctx, mmap, 2, SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, 0),
			   SCMP_A3(SCMP_CMP_MASKED_EQ, MAP_SHARED | MAP_GROWSDOWN, 0));
	// Allow mprotect only if no PROT_EXEC
	ALLOW_RULE(ctx, mprotect, 1, SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, 0));
	// Safe fcntl flags
	// fcntl F_GETFD || F_SETFD
	ALLOW_RULE(ctx, fcntl, 1, SCMP_A1(SCMP_CMP_EQ, F_GETFD, 0));
	ALLOW_RULE(ctx, fcntl, 1, SCMP_A1(SCMP_CMP_EQ, F_SETFD, 0));
	// fcntl F_GETFL || F_SETFL
	ALLOW_RULE(ctx, fcntl, 1, SCMP_A1(SCMP_CMP_EQ, F_GETFL, 0));
	ALLOW_RULE(ctx, fcntl, 1, SCMP_A1(SCMP_CMP_EQ, F_SETFL, 0));
	// fcntl F_DUPFD || F_DUPFD_CLOEXEC
	ALLOW_RULE(ctx, fcntl, 1, SCMP_A1(SCMP_CMP_EQ, F_DUPFD, 0));
	ALLOW_RULE(ctx, fcntl, 1, SCMP_A1(SCMP_CMP_EQ, F_DUPFD_CLOEXEC, 0));

	int ret = seccomp_load(ctx);
	seccomp_release(ctx);

	if (ret != 0) // Failed to apply seccomp filter
		return -1;
	return 0;
error:
	seccomp_release(ctx);
	return -1;
#elif defined(__FreeBSD__)
	int fd_whitelist[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, input_fd,
						  output_fd};
	int fd_count = sizeof(fd_whitelist) / sizeof(fd_whitelist[0]);
	unsigned long ioctl_cmds[] = {TIOCGWINSZ, TIOCGETA};

	cap_rights_t rights;
	cap_rights_init(&rights, CAP_WRITE, CAP_READ, CAP_SEEK, CAP_FSTAT,
					CAP_IOCTL);

	for (int i = 0; i < fd_count; i++) {
		if (cap_rights_limit(fd_whitelist[i], &rights) != 0)
			return -1;
		if (cap_ioctls_limit(fd_whitelist[i], ioctl_cmds, 2) != 0)
			return -1;
	}

	if (cap_enter() != 0)
		return -1;
	return 0;
#elif defined(__OpenBSD__)
	// Pledge "stdio" which only allows basic file operations on already open
	// files and other required process syscalls
	if (pledge("stdio", NULL) != 0) {
		perror("pledge");
		return -1;
	}

	return 0;
#else
	return -1; // Fallback for other OS (say the sandbox failed to init)
#endif // OS checks
#endif // NO_SANDBOX check
}
