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

static void handle_plt_call(
    tracee_t *tracee, struct user_regs_struct *regs, unsigned long long addr)
{
	char *sym_name = elf_get_plt_name(tracee, addr);
	if (sym_name == NULL) {
		pr_err("elf_get_plt_name failed");
		return;
	}

	pr_info_raw("%s(%#llx , %#llx, %#llx, %#llx)\n", sym_name, regs->rdi,
	    regs->rsi, regs->rdx, regs->rcx);
}

int main(int argc, char *argv[])
{
	tracee_setup(argc, argv, &tracee);
	elf_plt_init(&tracee);

	int wstatus = 0;
	// if using PID mode then start directly with singlestep
	int trace_type = tracee.execd ? PTRACE_SINGLESTEP : PTRACE_SYSCALL;
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
				pr_info("child exited, exiting tracer");
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
			if (elf_mem_va_base(&tracee) < 0) {
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
			unsigned long long addr = CALL_TO_VA(regs.rip, instr);
			// If the instruction falls within the PLT address
			if (addr > tracee.plt_start && addr < tracee.plt_end) {
				handle_plt_call(&tracee, &regs, addr);
			}
		}

	tracee_continue:
		TRACEE_CONT_TRACE(trace_type);
	}

	return 0;
err:
	ptrace(PTRACE_DETACH, tracee.pid, NULL, NULL);
	return 1;
}
