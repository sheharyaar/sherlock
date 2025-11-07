/*
 * Irene - Library call tracer
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#define _GNU_SOURCE
#include "log.h"
#include "tracee.h"
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define TRACEE_CONT_TRACE(mode)                                                \
	do {                                                                   \
		if (ptrace(mode, tracee.pid, NULL, 0) == -1) {                 \
			pr_err("ptrace cont err: %s", strerror(errno));        \
			goto err;                                              \
		}                                                              \
	} while (0)

static tracee_t tracee;

int main(int argc, char *argv[])
{
	print_libs(argv[2]);
	setup(argc, argv, &tracee);

	int wstatus = 0;
	int trace_type = PTRACE_SYSCALL;
	long instr = 0;
	struct user_regs_struct regs;

	while (1) {
		wstatus = 0;
		if (waitpid(tracee.pid, &wstatus, 0) < 0) {
			pr_err("waitpid err: %s", strerror(errno));
			goto err;
		}

		// Ptrace-stopped tracees are reported as returns with
		// WIFSTOPPED(status) true. See manpage ptrace(2).
		if (!WIFSTOPPED(wstatus)) {
			if (WIFEXITED(wstatus)) {
				pr_err("child exited, exiting tracer");
				return 1;
			}
			pr_warn("tracee stopped, not by ptrace\n");
			goto tracee_continue;
		}

		// fetch RIP value
		if (ptrace(PTRACE_GETREGS, tracee.pid, NULL, &regs) == -1) {
			pr_err("peekuser error: %s", strerror(errno));
			goto err;
		}

		if (wstatus >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
			pr_debug("child execed");
			// fetch the memory map base
			if (get_mem_va_base(&tracee) < 0) {
				pr_err("could not get tracee memory VA "
				       "base "
				       "address, trace failed");
				goto err;
			}

			tracee.execd = true;
			trace_type = PTRACE_SINGLESTEP;
		}

		// the child has not yet execed, the memory maps wont be updated
		// yet, wait for exec
		if (!tracee.execd)
			goto tracee_continue;

		// fetch the instruction at the RIP. The instructions are in
		// .text section
		instr = ptrace(PTRACE_PEEKTEXT, tracee.pid, regs.rip, NULL);
		if (instr == -1) {
			pr_err("peektext error: %s", strerror(errno));
			goto err;
		}

		// Check if the instruction is 'call'. e8 denotes to a near call
		// with 32 bit address Check AMD64 manuals for this
		if ((instr & 0xFF) == 0xe8) {
			pr_debug("Called VA: %#llx",
			    // convert the call address to Virtual Address
			    CALL_TO_VA(regs.rip, instr, tracee.va_base));
		}

	tracee_continue:
		TRACEE_CONT_TRACE(trace_type);
	}

	return 0;
err:
	ptrace(PTRACE_DETACH, tracee.pid, NULL, NULL);
	return 1;
}
