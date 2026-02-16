#if !defined(NO_SANDBOX)
#if defined(__linux__)
#define _GNU_SOURCE
#endif // defined(__linux__)
#include "utils.h"
#include <fcntl.h>
#include <unistd.h>

#if defined(__linux__)
#include <errno.h>
#include <sched.h>
#include <seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#if defined(HAS_LANDLOCK_H)
#include <linux/landlock.h>
#include <linux/types.h>
#include <sys/syscall.h>

// defined undefined ACCESS_FS bits for older landlock.h headers
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 12)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 14)
#endif

// define undefined ACCESS_NET bits for older landlock.h headers
#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

// define undefined SCOPED bits for older landlock.h headers
#ifndef LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#endif
#ifndef LANDLOCK_SCOPE_SIGNAL
#define LANDLOCK_SCOPE_SIGNAL (1ULL << 1)
#endif

// Manually define landlock ruleset struct to prevent compilation errors on <
// kernel 6.11 which doesnt have the .scoped field, and .handled_access_net
// introduced in kernel 6.7 This will continue to compile if new fields are
// added, as the kernel treats a lower size as an older program not aware of
// newer fields
struct landlock_ruleset_attr_abiv6 {
	__u64 handled_access_fs;
	__u64 handled_access_net; // ABI v4 (kernel 6.7)
	__u64 scoped;			  // ABI v6 (kernel 6.11)
};

static long get_landlock_abi(void) {
	return syscall(SYS_landlock_create_ruleset, NULL, 0,
				   LANDLOCK_CREATE_RULESET_VERSION);
}

// void* attr to account for custom abiv6 struct
static long landlock_create_ruleset(const void* attr, size_t size,
									uint32_t flags) {
	return syscall(SYS_landlock_create_ruleset, attr, size, flags);
}

static long landlock_restrict_self(int ruleset_fd, uint32_t flags) {
	return syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
}
#endif // defined(HAS_LANDLOCK_H)

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

#elif defined(__FreeBSD__)
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <termios.h>
#endif // OS checks

#endif // !defined(NO_SANDBOX)

// Forward definitions
#if defined(__linux__)
int linux_enter_sandbox(int input_fd, int output_fd);
#elif defined(__OpenBSD__)
int openbsd_enter_sandbox(void);
#elif defined(__FreeBSD__)
int freebsd_enter_sandbox(int input_fd, int output_fd);
#endif // OS CHECKS

int apply_sandbox(int input_fd, int output_fd) {
#if defined(NO_SANDBOX)
	return -1;
#else // !defined(NO_SANDBOX)
#if defined(__linux__)
	return linux_enter_sandbox(input_fd, output_fd);
#elif defined(__OpenBSD__)
	return openbsd_enter_sandbox();
#elif defined(__FreeBSD__)
	return freebsd_enter_sandbox(input_fd, output_fd);
#else
	// Fallback for non-supported OS
	return -1;
#endif // OS CHECKS
#endif // defined(NO_SANDBOX) || !defined(NO_SANDBOX)
}

#if defined(__linux__)
// Forward definitions
int linux_unveil_filesystem(void);
int linux_drop_all_caps(void);
int linux_init_seccomp(int input_fd, int output_fd);

int linux_enter_sandbox(int input_fd, int output_fd) {
	// Prevent gaining of new privileges (required for landlock and seccomp)
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		perror("[SANDBOX] prctl(PR_SET_NO_NEW_PRIVS)");
		return -1;
	}

	// Hide filesystem from view (landlock or fallback to chroot)
	if (linux_unveil_filesystem() != 0)
		return -1;

	// Drop all capabilities from the current and bounding set
	if (linux_drop_all_caps() != 0)
		return -1;

	// Filter all syscalls through a seccomp whitelist
	if (linux_init_seccomp(input_fd, output_fd) != 0)
		return -1;

	return 0;
}

int linux_unveil_filesystem(void) {
	int chrooted = 0;
	if (unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC |
				CLONE_NEWUTS | CLONE_NEWPID) != 0)
	{
		perror("[SANDBOX] unshare(CLONE_NEWUSER | CLONE_NEWNS)");
		eprintf("[SANDBOX] chroot failed, falling back to landlock..");
		goto try_landlock;
	}

	// Chroot into safe directory
	const char* jail = "/proc/self/fdinfo";
	if (chdir(jail) != 0 || chroot(jail) != 0) {
		perror("[SANDBOX] chdir/chroot");
		eprintf("[SANDBOX] chroot failed, attempting to landlock..");
		goto try_landlock;
	}
	if (chdir("/") != 0) {
		perror("[SANDBOX] chdir");
		eprintf("[SANDBOX] chroot failed, attempting landlock..");
		goto try_landlock;
	}

	// If landlock fails, chrooted = 1 will cause it to be non-fatal
	chrooted = 1;

	// Also attempt to landlock for extra protections against chroot escapes
	// This will usually be the only unveil protection if usernamespaces are
	// disabled on the running kernel It is good enough by itself that chroot
	// fail but landlock succeeds it is not fatal. But chroot + landlock is
	// always nice

try_landlock:
#if defined(HAS_LANDLOCK_H)
	; // Satisfy < c23 standards (label following a declaration)
	long abi = get_landlock_abi();
	if (abi < 1) {
		eprintf("[SANDBOX] landlock not supported by kernel");
		if (chrooted == 1) {
			eprintf("[SANDBOX] landlock failed but chroot succeeded, you are "
					"still sandboxed.");
			return 0;
		}
		return -1;
	}

	__u64 ruleset_access_fs_mask = 0;
	ruleset_access_fs_mask |=
		(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
		 LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
		 LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
		 LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
		 LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
		 LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		 LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER |
		 LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_IOCTL_DEV);

	struct landlock_ruleset_attr_abiv6 ruleset_attr = {
		.handled_access_fs = ruleset_access_fs_mask,
		.handled_access_net =
			LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
		.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL,
	};

	size_t size = sizeof(ruleset_attr);

	// Remove features the current ABI doesnt understand
	if (abi < 6)
		ruleset_attr.scoped = 0;
	if (abi < 5)
		ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
	if (abi < 4)
		ruleset_attr.handled_access_net = 0;
	if (abi < 3)
		ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
	if (abi < 2)
		ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;

	// Make sure the struct size passed to syscall matches the kernel's
	// supported ABI struct size
	if (abi < 4)
		size = offsetof(struct landlock_ruleset_attr_abiv6, handled_access_net);
	else if (abi < 6)
		size = offsetof(struct landlock_ruleset_attr_abiv6, scoped);
	else
		size = sizeof(ruleset_attr); // size of abi v6 struct

	// Create a ruleset file descriptor
	int ruleset_fd = (int)landlock_create_ruleset(&ruleset_attr, size, 0);
	if (ruleset_fd < 0) {
		eprintf("[SANDBOX] Failed to create landlock ruleset");
		if (chrooted == 1) {
			eprintf("[SANDBOX] landlock failed but chroot succeeded, you are "
					"still sandboxed.");
			return 0;
		}
		return -1;
	}

	// Restrict self according to the ruleset FD
	if (landlock_restrict_self(ruleset_fd, 0) < 0) {
		eprintf("[SANDBOX] Failed to restrict self with landlock");
		close(ruleset_fd);
		if (chrooted == 1) {
			eprintf("[SANDBOX] landlock failed but chroot succeeded, you are "
					"still sandboxed.");
			return 0;
		}
		return -1;
	}

	close(ruleset_fd);
	return 0;

#endif // defined(HAS_LANDLOCK_H)
}

int linux_drop_all_caps(void) {
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

	return 0;
}

int linux_init_seccomp(int input_fd, int output_fd) {
	int fd_whitelist[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, input_fd,
						  output_fd};
	int fd_count = sizeof(fd_whitelist) / sizeof(fd_whitelist[0]);

#if defined(NACRYPT_SECCOMP_DEBUG)
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);
#else
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
#endif // defined(NACRYPT_SECCOMP_DEBUG) || !defined(NACRYPT_SECCOMP_DEBUG)
	if (ctx == NULL)
		return -1;
// Macro to allow a syscall under certain conditions
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
}
#endif // defined(__linux__)

#if defined(__OpenBSD__)
int openbsd_enter_sandbox(void) {
	// Pledge "stdio" which only allows basic file operations on already open
	// files and other required process syscalls
	if (pledge("stdio", NULL) != 0) {
		perror("pledge");
		return -1;
	}

	return 0;
}
#endif // defined(__OpenBSD__)

#if defined(__FreeBSD__)
int freebsd_enter_sandbox(int input_fd, int output_fd) {
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
}
#endif // defined(__FreeBSD__)
