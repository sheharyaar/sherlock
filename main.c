#define _GNU_SOURCE
#include "log.h"
#include "syscall.h"
#include "trace.h"
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static tracee_t tracee;

void print_help(int ret)
{
	pr_info_raw("usage:\n");
	pr_info_raw("./sherlock --pid pid\n");
	pr_info_raw("./sherlock --exec program arg1 arg2 ...\n");
	exit(ret);
}

int attach_and_start(int options)
{
	// attach to the program
	if (ptrace(PT_ATTACH, tracee.pid, NULL, 0) == -1) {
		pr_err("ptrace failed: %s", strerror(errno));
		return -1;
	}
	pr_debug("ptrace attach");

	// need the tracee to stop to set options
	if (waitpid(tracee.pid, NULL, 0) == -1) {
		pr_err("waitpid err: %s", strerror(errno));
		goto err;
	}
	pr_debug("waitpid attach");

	// need only the SYSCALL related signals
	if (ptrace(PTRACE_SETOPTIONS, tracee.pid, NULL, options) == -1) {
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
	return 0;
err:
	ptrace(PTRACE_DETACH, tracee.pid, NULL, NULL);
	return -1;
}

void setup(int argc, char *argv[])
{
	if (argc < 2)
		print_help(1);

	if (strncmp(argv[1], "--pid", strlen("--pid")) == 0) {
		tracee.pid = atoi(argv[2]);
		tracee.state = UNATTACHED;
		pr_info("tracing PID: %d", tracee.pid);

		if (attach_and_start(PTRACE_O_TRACESYSGOOD) == -1) {
			pr_err("attaching to pid failed");
			exit(1);
		}
	} else if (strncmp(argv[1], "--exec", strlen("--exec")) == 0) {
		if (argc < 3) {
			print_help(1);
		}

		// setup pipe for communication
		int pipefd[2];
		int flag;
		if (pipe(pipefd) == -1) {
			pr_err("error in pipefd: %s", strerror(errno));
			exit(1);
		}

		int ret = fork();
		if (ret == -1) {
			pr_err("fork failed: %s", strerror(errno));
			exit(1);
		}

		// handle child
		if (ret == 0) {
			close(pipefd[1]);
			if (read(pipefd[0], &flag, sizeof(int)) == -1) {
				pr_err(
				    "error in child read: %s", strerror(errno));
				_exit(1);
			}

			// now exec into the program
			if (execvp(argv[2], &argv[2]) == -1) {
				pr_err(
				    "error in child exec: %s", strerror(errno));
				_exit(1);
			}
		} else {
			tracee.pid = ret;
			close(pipefd[0]);

			// perform the attach here
			if (attach_and_start(PTRACE_O_TRACESYSGOOD |
				PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC) == -1) {
				pr_err("attach failed for exec child");
				goto parent_err;
			}

			if (write(pipefd[1], &flag, sizeof(int)) == -1) {
				pr_err("error in parent write: %s",
				    strerror(errno));
				// kill the child
				goto parent_err;
			}
			return;

		parent_err:
			kill(tracee.pid, SIGKILL);
			exit(1);
		}
	} else if (strncmp(argv[1], "--help", strlen("--help")) == 0) {
		print_help(0);
	} else {
		pr_err("invalid arguments");
		print_help(1);
	}
}

/*
Source: System V ABI for AMD64 structure, section A.2.1 (Calling Conventions)
Instead of this, can also use `PTRACE_GET_SYSCALL_INFO` to get syscall args.
That also does these internally.
*/
void print_entry_args(struct user_regs_struct *reg)
{
	// arguments
	pr_info_raw("%lld, ", reg->rdi);
	pr_info_raw("%lld, ", reg->rsi);
	pr_info_raw("%lld, ", reg->rdx);
	pr_info_raw("%lld, ", reg->r10);
	pr_info_raw("%lld, ", reg->r8);
	pr_info_raw("%lld, ", reg->r9);
}

int main(int argc, char *argv[])
{
	setup(argc, argv);

	int wstatus = 0;
	struct user_regs_struct regs;
	while (1) {
		wstatus = 0;
		if (waitpid(tracee.pid, &wstatus, 0) < 0) {
			pr_err("waitpid err: %s", strerror(errno));
			goto err;
		}
		pr_debug("waitpid syscall");

		// Ptrace-stopped tracees are reported as returns with
		// WIFSTOPPED(status) true. See manpage ptrace(2).
		if (!WIFSTOPPED(wstatus)) {
			pr_warn("tracee stopped, not by ptrace\n");
			tracee_continue_syscall();
			continue;
		}

		// Using PTRACE_O_TRACESYSGOOD returns (SIGTRAP | 0x80) to the
		// tracer. See manpage ptrace(2)
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
			pr_info_raw("\n) = %lld\n", regs.rax);
		}

		tracee_continue_syscall();
	}

	return 0;
err:
	ptrace(PTRACE_DETACH, tracee.pid, NULL, NULL);
	return 1;
}
