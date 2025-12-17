#ifndef NO_SECCOMP
#include <seccomp.h>
#endif //NO_SECCOMP
#include <stdbool.h>
#include <sys/prctl.h>
#include <stdio.h>

bool apply_seccomp_filter(void) {
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		perror("PR_SET_NO_NEW_PRIVS failed");
		return false;
	}

	#ifndef NO_SECCOMP
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 1,
					SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, 0));
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 1,
					SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, 0));
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);

	if (seccomp_load(ctx) != 0) return false;
	seccomp_release(ctx);
	#endif //NO_SECCOMP
	
	return true;
}
