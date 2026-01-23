/*
 * Watson - System call tracer
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#define _GNU_SOURCE
#include "log.h"
#include "syscall_defs.h"
#include "tracee_defs.h"
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static tracee_t tracee;

void print_help(int ret)
{
	pr_info_raw("usage:\n");
	pr_info_raw("./watson --pid pid\n");
	pr_info_raw("./watson --exec program arg1 arg2 ...\n");
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

		tracee.execd = true;
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
			tracee.execd = false;
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
void print_entry_args(const syscall_t *sys, struct user_regs_struct *reg)
{
	// arguments
	unsigned long long args[SYSCALL_ARGS_MAX] = {
		reg->rdi,
		reg->rsi,
		reg->rdx,
		reg->r10,
		reg->r8,
		reg->r9,
	};

	if (!sys->print) {
		pr_info_raw("%lld, ", args[0]);
		pr_info_raw("%lld, ", args[1]);
		pr_info_raw("%lld, ", args[2]);
		pr_info_raw("%lld, ", args[3]);
		pr_info_raw("%lld, ", args[4]);
		pr_info_raw("%lld", args[5]);
	} else {
		sys->print(&tracee, args);
	}
}

int main(int argc, char *argv[])
{
	setup(argc, argv);

	bool terminate = false;
	int wstatus = 0;
	struct user_regs_struct regs;
	while (!terminate) {
		wstatus = 0;
		if (waitpid(tracee.pid, &wstatus, 0) < 0) {
			pr_err("waitpid err: %s", strerror(errno));
			goto err;
		}

		// Ptrace-stopped tracees are reported as returns with
		// WIFSTOPPED(status) true. See manpage ptrace(2).
		if (!WIFSTOPPED(wstatus)) {
			if (WIFEXITED(wstatus)) {
				terminate = true;
				goto tracee_continue;
			}
			pr_warn("tracee stopped, not by ptrace\n");
			goto tracee_continue;
		}

		// Using PTRACE_O_TRACESYSGOOD returns (SIGTRAP | 0x80) to the
		// tracer. See manpage ptrace(2)
		if (WSTOPSIG(wstatus) != (SIGTRAP | 0x80)) {
			if (wstatus >> 8 ==
			    (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
				// was this exec ?
				tracee.execd = true;
			} else {
				pr_warn(
				    "stopped, not by syscall, but by (%s)\n",
				    strsignal(WSTOPSIG(wstatus)));
				goto tracee_continue;
			}
		}

		// if the tracee has not execed, skip the syscall
		if (!tracee.execd)
			goto tracee_continue;

		memset(&regs, 0, sizeof(struct user_regs_struct));
		if (ptrace(PTRACE_GETREGS, tracee.pid, NULL, &regs) == -1) {
			pr_err("getregs error: %s", strerror(errno));
			goto err;
		}

		// this can be flaky, better use PTRACE_GET_SYSCALL_INFO,
		// see manpage ptrace(2)
		if (regs.rax == (unsigned long long)-ENOSYS) {
			const syscall_t *sys = get_syscall(regs.orig_rax);
			if (sys == NULL) {
				pr_err(
				    "unknow system call: %lld", regs.orig_rax);
				goto tracee_continue;
			}

			tracee.signal = regs.orig_rax;
			pr_info_raw("%s(", sys->name);
			print_entry_args(sys, &regs);
		} else {
			pr_info_raw(") = %lld\n", regs.rax);
		}

	tracee_continue:
		if (!terminate)
			tracee_continue_syscall();
	}

	return 0;
err:
	ptrace(PTRACE_DETACH, tracee.pid, NULL, NULL);
	return 1;
}
