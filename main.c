/* TODO: handle PTRACE_CONT if not stopped by syscall enter or stop */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/user.h>
#include "strsyscall.h"
#include "log.h"

#define tracee_continue_syscall()                                        \
	do {                                                             \
		if (ptrace(PTRACE_SYSCALL, tracee.pid, NULL, 0) == -1) { \
			pr_err("ptrace cont err: %s", strerror(errno));  \
			goto err;                                        \
		}                                                        \
	} while (0)

typedef enum state { UNATTACHED, ENTRY, EXIT } state_t;

typedef struct TRACEE {
	pid_t pid;
	state_t state;
} tracee_t;

static bool terminate = 0;
static tracee_t tracee;

void setup(int argc, char *argv[])
{
	if (argc != 2) {
		pr_err("invalid number of arguments received (%d)", argc);
		exit(1);
	}

	// TODO: Add signal handler and exit handlers
	tracee.pid = atoi(argv[1]);
	tracee.state = UNATTACHED;
	pr_info("tracing PID: %d", tracee.pid);
}

/* 
	Source: System V ABI for AMD64 structure, section A.2.1 (Calling Conventions)
	Instead of this, can also use `PTRACE_GET_SYSCALL_INFO` to get syscall args.
	That also does these internally.
*/
void print_entry_args(struct user_regs_struct *reg)
{
	// arguments
	pr_info_raw("\t%016llx,", reg->rdi);
	pr_info_raw("\t%016llx,", reg->rsi);
	pr_info_raw("\t%016llx,", reg->rdx);
	pr_info_raw("\t%016llx,", reg->r10);
	pr_info_raw("\t%016llx,", reg->r8);
	pr_info_raw("\t%016llx,", reg->r9);
}

int main(int argc, char *argv[])
{
	setup(argc, argv);

	// attach to the program
	if (ptrace(PT_ATTACH, tracee.pid, NULL, 0) == -1) {
		pr_err("ptrace failed: %s", strerror(errno));
		return 1;
	}
	pr_debug("ptrace attach");

	// need the tracee to stop to set options
	if (waitpid(tracee.pid, NULL, 0) == -1) {
		pr_err("waitpid err: %s", strerror(errno));
		goto err;
	}
	pr_debug("waitpid attach");

	// need only the SYSCALL related signals
	if (ptrace(PTRACE_SETOPTIONS, tracee.pid, NULL,
		   PTRACE_O_TRACESYSGOOD) == -1) {
		pr_err("ptrace setopts failed: %s", strerror(errno));
		goto err;
	}
	pr_debug("ptrace setoptions");

	// start tracing the tracee at syscalls
	if (ptrace(PTRACE_SYSCALL, tracee.pid, NULL, 0) < 0) {
		pr_err("getregs error: %s", strerror(errno));
		goto err;
	}
	pr_debug("ptrace syscall");

	int wstatus = 0;
	struct user_regs_struct regs;
	while (!terminate) {
		wstatus = 0;
		if (waitpid(tracee.pid, &wstatus, 0) < 0) {
			pr_err("waitpid err: %s", strerror(errno));
			goto err;
		}
		pr_debug("waitpid syscall");

		// Ptrace-stopped tracees are reported as returns with WIFSTOPPED(status) true.
		// See manpage ptrace(2).
		if (!WIFSTOPPED(wstatus)) {
			pr_warn("tracee stopped, not by ptrace\n");
			tracee_continue_syscall();
			continue;
		}

		// Using PTRACE_O_TRACESYSGOOD returns (SIGTRAP | 0x80) to the tracer.
		// See manpage ptrace(2)
		if (WSTOPSIG(wstatus) != (SIGTRAP | 0x80)) {
			pr_warn("stopped, not by syscall\n");
			tracee_continue_syscall();
			continue;
		}

		// print_registers
		memset(&regs, 0, sizeof(struct user_regs_struct));
		if (ptrace(PTRACE_GETREGS, tracee.pid, NULL, &regs) == -1) {
			pr_err("peekuser error: %s", strerror(errno));
			goto err;
		}

		// this can be flaky, better use PTRACE_GET_SYSCALL_INFO,
		// see manpage ptrace(2)
		if (regs.rax == (unsigned long long)-ENOSYS) {
			pr_info_raw("%s(", str_syscall(regs.orig_rax));
			print_entry_args(&regs);
		} else {
			pr_info_raw(") = %lld", regs.rax);
		}

		tracee_continue_syscall();
	}

	return 0;

err:
	ptrace(PTRACE_DETACH, tracee.pid, NULL, NULL);
	return 1;
}
