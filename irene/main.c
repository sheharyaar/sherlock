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

static tracee_t tracee;

static void handle_plt_call(tracee_t *tracee)
{
	// fetch RIP value
	struct user_regs_struct regs;
	if (ptrace(PTRACE_GETREGS, tracee->pid, NULL, &regs) == -1) {
		pr_err("peekuser error: %s", strerror(errno));
		return;
	}

	// check the library name associated with this addr.

	unsigned long long addr = regs.rip - 1;
	char *sym_name = elf_get_plt_name(tracee, addr);
	if (sym_name == NULL) {
		pr_err("elf_get_plt_name failed");
		return;
	}

	pr_info_raw("%s(%#llx , %#llx, %#llx, %#llx)\n", sym_name, regs.rdi,
	    regs.rsi, regs.rdx, regs.rcx);

	// restore original val, format: cc 35 ca 2f 00 00 -> ff 35 ca 2f 00 00
	// (in reverse due to endian order)
	long break_val = 0;
	errno = 0;
	break_val = ptrace(PTRACE_PEEKTEXT, tracee->pid, addr, NULL);
	if (break_val == -1 && errno != 0) {
		pr_err("error in PTRACE_PEEKTEXT, could mess up tracing: %s",
		    strerror(errno));
		return;
	}

	long orig_val = (break_val & 0xffffffffffffff00UL) | 0xff;
	pr_debug("break_val=%#lx, orig_val=%#lx", break_val, orig_val);
	if (ptrace(PTRACE_POKETEXT, tracee->pid, addr, orig_val) == -1) {
		pr_err("error in PTRACE_POKETEXT, could mess up tracing: %s",
		    strerror(errno));
		return;
	}

	// restore the RIP register and retrigger
	regs.rip -= 1;
	if (ptrace(PTRACE_SETREGS, tracee->pid, NULL, &regs) == -1) {
		pr_err("error in setting reg for breakpoint, can mess up the "
		       "program: %s",
		    strerror(errno));
		return;
	}

	// single step and restore the breakpoint
	if (ptrace(PTRACE_SINGLESTEP, tracee->pid, NULL, NULL) == -1) {
		pr_err("error in ptrace signlestep: %s", strerror(errno));
		return;
	}

	// wait for singlestep
	if (waitpid(tracee->pid, NULL, 0) < 0) {
		pr_err("handle_plt_call waitpid err: %s", strerror(errno));
		return;
	}

	// restore breakpoint, format: ff 35 ca 2f 00 00 -> cc 35 ca 2f 00 00
	// (in reverse order due to endian)
	if (ptrace(PTRACE_POKETEXT, tracee->pid, addr, break_val) == -1) {
		pr_err("error in PTRACE_POKETEXT breakpoint data, could mess "
		       "up tracing: %s",
		    strerror(errno));
		return;
	}
}

int main(int argc, char *argv[])
{
	if (tracee_setup(argc, argv, &tracee) < 0) {
		pr_err("tracee setup failed");
		exit(1);
	}

	if (elf_plt_init(&tracee) < 0) {
		pr_err("elf_plt_init failed");
		ptrace(PTRACE_DETACH, tracee.pid, NULL, NULL);
		exit(1);
	}

	int wstatus = 0;

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
				return 0;
			}
			pr_warn("tracee stopped, not by ptrace\n");
			goto tracee_continue;
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

			// break all PLTs
			if (elf_break_plt_all(&tracee) == -1) {
				pr_err("adding breakpoints failed");
				goto err;
			}

			tracee.execd = true;
			goto tracee_continue;
		}

		// the child has not yet execed, the memory maps wont be updated
		// yet, wait for exec
		if (!tracee.execd)
			goto tracee_continue;

		if (WSTOPSIG(wstatus) == SIGTRAP) {
			handle_plt_call(&tracee);
		}

	tracee_continue:
		if (ptrace(PTRACE_CONT, tracee.pid, NULL, NULL) == -1) {
			pr_err("ptrace cont err: %s", strerror(errno));
			goto err;
		}
	}

	return 0;
err:
	ptrace(PTRACE_DETACH, tracee.pid, NULL, NULL);
	return 1;
}
