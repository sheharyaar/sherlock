/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include <sherlock/breakpoint.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

// TODO: Check for plt_need_resolve and patch the PLT entry for this symbol
int breakpoint_add(tracee_t *tracee, unsigned long long bpaddr, symbol_t *sym)
{

	long data = ptrace(PTRACE_PEEKTEXT, tracee->pid, bpaddr, NULL);
	if (data == -1 && errno != 0) {
		// some error occured
		if (errno == EIO || errno == EFAULT) {
			pr_info_raw("the requested memory address(%#llx) is "
				    "not accessible\n",
			    bpaddr);
		} else {
			pr_err("reading the address(%#llx) failed: %s", bpaddr,
			    strerror(errno));
		}

		// this is not a critical error
		return 0;
	}

	pr_debug("instruction at address(%#llx): %#lx", bpaddr, (data & 0xFF));

	breakpoint_t *bp = (breakpoint_t *)calloc(1, sizeof(breakpoint_t));
	if (bp == NULL) {
		pr_err("breakpoint_add: cannot allocate breakpoint");
		return -1;
	}

	bp->addr = bpaddr;
	bp->value = data;
	bp->idx = 0;
	bp->counter = 0;
	bp->sym = sym;
	if (tracee->bp) {
		bp->idx = tracee->bp->idx + 1;
	}
	bp->next = tracee->bp;
	tracee->bp = bp;

	unsigned long val = (data & 0xFFFFFFFFFFFFFF00UL) | 0xCCUL;
	if (ptrace(PTRACE_POKETEXT, tracee->pid, bpaddr, val) == -1) {
		pr_err("breakpoint_add: error in PTRACE_POKETEXT- %s",
		    strerror(errno));
		return -1;
	}

	pr_info_raw("Breakpoint %d added at address=%#llx\n", bp->idx, bpaddr);
	return 0;
}

static void breakpoint_print(breakpoint_t *bp)
{
	if (bp->sym != NULL) {
		symbol_t *sym = bp->sym;
		pr_info_raw("Breakpoint %d, '%s' () at %#llx in %s\n", bp->idx,
		    sym->name, sym->addr,
		    sym->file_name == NULL ? "??" : sym->file_name);
	} else {
		pr_info_raw("Breakpoint %d, %#llx\n", bp->idx, bp->addr);
	}
}

void breakpoint_printall(tracee_t *tracee)
{
	breakpoint_t *bp = tracee->bp;
	while (bp) {
		// TODO_LATER: improve symbol information here
		// [n]: 0x123fe12 in <func> at <file:line>, hit_counter=m
		pr_info_raw("[%d]: %#llx, hit_count=%d\n", bp->idx, bp->addr,
		    bp->counter);
		pr_debug("value: %#lx", bp->value);
		bp = bp->next;
	}
}

int breakpoint_handle(tracee_t *tracee)
{
	struct user_regs_struct regs;
	if (ptrace(PTRACE_GETREGS, tracee->pid, NULL, &regs) == -1) {
		pr_err("breakpoint_handle: error in getting registers: %s",
		    strerror(errno));
		return -1;
	}

	bool found = false;
	breakpoint_t *bp = tracee->bp;
	while (bp) {
		if (bp->addr + 1 == regs.rip) {
			found = true;
			break;
		}

		bp = bp->next;
	}

	// replace the change text and reset the rip
	if (found) {
		++bp->counter;
		breakpoint_print(bp);
		unsigned long val = bp->value;
		if (ptrace(PTRACE_POKETEXT, tracee->pid, bp->addr, val) == -1) {
			pr_err("breakpoint_handle: ptrace POKETEXT err - %s",
			    strerror(errno));
			return -1;
		}

		regs.rip -= 1;
		if (ptrace(PTRACE_SETREGS, tracee->pid, NULL, &regs) == -1) {
			pr_err("breakpoint_handle: ptrace SETREGS error - %s",
			    strerror(errno));
			return -1;
		}

		// single step and reset
		if (ptrace(PTRACE_SINGLESTEP, tracee->pid, NULL, NULL) == -1) {
			pr_err("error in breakpoint singleste: %s",
			    strerror(errno));
			return -1;
		}

		int wstatus = 0;
		if (waitpid(tracee->pid, &wstatus, 0) < 0) {
			pr_err("waitpid err: %s", strerror(errno));
			return -1;
		}

		if (!WIFSTOPPED(wstatus)) {
			pr_err("not stopped by SIGSTOP");
			return -1;
		}

		// restore the breakpoint
		val = (bp->value & 0xFFFFFFFFFFFFFF00UL) | 0xCCUL;
		if (ptrace(PTRACE_POKETEXT, tracee->pid, bp->addr, val) == -1) {
			pr_err(
			    "breakpoint_handle: error in PTRACE_POKETEXT- %s",
			    strerror(errno));
			return -1;
		}
	}

	return 0;
}

void breakpoint_cleanup(tracee_t *tracee)
{
	pr_debug("breakpoint cleanup");
	breakpoint_t *bp = tracee->bp;
	breakpoint_t *t = NULL;
	while (bp != NULL) {
		t = bp;
		bp = bp->next;
		free(t);
	}
	tracee->bp = NULL;
}