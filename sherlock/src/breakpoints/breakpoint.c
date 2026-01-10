/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#include <sherlock/breakpoint.h>
#include <sherlock/sym.h>
#include <errno.h>
#include <link.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#define DO_SINGLESTEP(tracee, err)                                             \
	do {                                                                   \
		if (ptrace(PTRACE_SINGLESTEP, tracee->pid, NULL, 0) == -1) {   \
			pr_err("error in singlestep");                         \
			return err;                                            \
		}                                                              \
                                                                               \
		int wstatus = 0;                                               \
		if (waitpid(tracee->pid, &wstatus, 0) < 0) {                   \
			pr_err("waitpid err: %s", strerror(errno));            \
			return err;                                            \
		}                                                              \
                                                                               \
		if (!WIFSTOPPED(wstatus)) {                                    \
			pr_err("not stopped by SIGSTOP");                      \
			return err;                                            \
		}                                                              \
	} while (0)

void breakpoint_delete(tracee_t *tracee, unsigned int idx)
{
	breakpoint_t **headp = &(tracee->bp_list);
	breakpoint_t *t = NULL;
	while (*headp != NULL) {
		if ((*headp)->idx == idx) {
			t = *headp;
			*headp = t->next;
			free(t);
			return;
		}
		headp = &((*headp)->next);
	}
}

int breakpoint_add(tracee_t *tracee, unsigned long long bpaddr, symbol_t *sym)
{
	long data = 0;
	if (bpaddr == 0) {
		if (sym == NULL) {
			pr_err("invalid address passed to breakpoint_add");
			return -1;
		}

		goto create_bp;
	}

	if (sym != NULL && sym->bp != NULL) {
		pr_info_raw("There is already a breakpoint for '%s' present",
		    sym->name);
	}

	data = ptrace(PTRACE_PEEKTEXT, tracee->pid, bpaddr, NULL);
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

	unsigned long val = (data & 0xFFFFFFFFFFFFFF00UL) | 0xCCUL;
	if (ptrace(PTRACE_POKETEXT, tracee->pid, bpaddr, val) == -1) {
		pr_err("breakpoint_add: error in PTRACE_POKETEXT- %s",
		    strerror(errno));
		return -1;
	}

	if (bpaddr == tracee->debug.r_brk_addr) {
		// this is a special breakpoint wont be added to the list
		tracee->debug.r_brk_val = data;
		pr_debug("added breakpoint to internal linker structure");
		return 0;
	}

create_bp:
	breakpoint_t *bp = (breakpoint_t *)calloc(1, sizeof(breakpoint_t));
	if (bp == NULL) {
		pr_err("breakpoint_add: cannot allocate breakpoint");
		return -1;
	}

	bp->addr = bpaddr;
	bp->value = data;
	bp->idx = 1;
	bp->counter = 0;
	bp->sym = sym;
	bp->is_plt_bp = false;
	if (tracee->bp_list) {
		bp->idx = tracee->bp_list->idx + 1;
	}
	bp->next = tracee->bp_list;
	tracee->bp_list = bp;

	if (sym != NULL) {
		sym->bp = bp;

		if (sym->section != NULL &&
		    strncmp(sym->section->name, ".plt", 4) == 0) {
			bp->is_plt_bp = 1;
		}
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
	breakpoint_t *bp = tracee->bp_list;
	while (bp) {
		pr_info_raw("[%d]: name=%s, address=%#llx, hit_count=%d\n",
		    bp->idx, bp->sym == NULL ? "??" : bp->sym->name, bp->addr,
		    bp->counter);
		pr_debug("value: %#lx", bp->value);
		bp = bp->next;
	}
}

// restores the original value and RIP for the bp being handled, this is the
// first phase of the breakpoint cycle
static int _breakpoint_restore_original(tracee_t *tracee,
    struct user_regs_struct *reg, unsigned long bpaddr, unsigned long bpval)
{
	if (ptrace(PTRACE_POKETEXT, tracee->pid, bpaddr, bpval) == -1) {
		pr_err("breakpoint_handle: ptrace POKETEXT err - %s",
		    strerror(errno));
		return -1;
	}

	if (reg) {
		if (ptrace(PTRACE_SETREGS, tracee->pid, NULL, reg) == -1) {
			pr_err("breakpoint_handle: ptrace SETREGS error - %s",
			    strerror(errno));
			return -1;
		}

		pr_debug("rip_final=%#llx", reg->rip);
	}
	return 0;
}

// restores the breakpoint at the address, this is the second phase of the
// breakpoint cycle
static int _breakpoint_restore_bp(
    tracee_t *tracee, unsigned long bpaddr, unsigned long bpval)
{
	// single step and reset
	DO_SINGLESTEP(tracee, -1);

	// restore the breakpoint
	unsigned long long val = (bpval & 0xFFFFFFFFFFFFFF00UL) | 0xCCUL;
	if (ptrace(PTRACE_POKETEXT, tracee->pid, bpaddr, val) == -1) {
		pr_err("breakpoint_handle: error in PTRACE_POKETEXT- %s",
		    strerror(errno));
		return -1;
	}

	return 0;
}

int breakpoint_pending(tracee_t *tracee)
{
	// nothing to do
	pr_debug("bp pending");
	if (tracee->pending_bp == NULL) {
		return 0;
	}

	breakpoint_t *bp = tracee->pending_bp;
	if (_breakpoint_restore_bp(tracee, bp->addr, bp->value) == -1) {
		pr_err("error in resuming breakpoint");
		return -1;
	}

	tracee->pending_bp = NULL;
	return 0;
}

int breakpoint_update(
    tracee_t *tracee, breakpoint_t *bp, unsigned long new_addr)
{
	// type other than GLOB_DAT
	if (bp->addr != 0) {
		// restore the old breakpoint
		if (_breakpoint_restore_original(
			tracee, NULL, bp->addr, bp->value) == -1) {
			pr_err("_breakpoint_restore_original failed");
			return -1;
		}
	}

	// add breakpoint to new place
	long data = ptrace(PTRACE_PEEKTEXT, tracee->pid, new_addr, 0);
	if (data == -1) {
		pr_err("unable to get data at new_addr");
		return -1;
	}

	// update the breakpoint
	unsigned long val = (data & 0xFFFFFFFFFFFFFF00UL) | 0xCCUL;
	if (ptrace(PTRACE_POKETEXT, tracee->pid, new_addr, val) == -1) {
		pr_err("updating breakpoint failed - %s", strerror(errno));
		return -1;
	}

	bp->value = data;
	bp->addr = new_addr;
	return 0;
}

tracee_state_e breakpoint_handle(tracee_t *tracee)
{
	pr_debug("breakpoint_handle");
	struct user_regs_struct regs;
	if (ptrace(PTRACE_GETREGS, tracee->pid, NULL, &regs) == -1) {
		pr_err("breakpoint_handle: error in getting registers: %s",
		    strerror(errno));
		return TRACEE_STOPPED;
	}

	pr_debug("rip=%#llx", regs.rip);

	// since 0xCC occupies 1 byte and rip points to next address
	regs.rip -= 1;

	if (regs.rip == tracee->debug.r_brk_addr) {
		if (_breakpoint_restore_original(tracee, &regs,
			tracee->debug.r_brk_addr,
			tracee->debug.r_brk_val) == -1) {
			pr_err("error in restoring original state to bp");
			return TRACEE_STOPPED;
		}

		// we have received the breakpoint from r_brk
		// update the map of symbols here
		if (sym_handle_dldbg_syms(tracee) == -1) {
			pr_err("error in handling internal debug structure");
			return TRACEE_ERR;
		}

		if (_breakpoint_restore_bp(tracee, tracee->debug.r_brk_addr,
			tracee->debug.r_brk_val) == -1) {
			pr_err("error in resuming after linker bp");
			return TRACEE_ERR;
		}

		if (ptrace(PTRACE_CONT, tracee->pid, NULL, 0) == -1) {
			pr_err("error in resuming tracee after linker bp: %s",
			    strerror(errno));
			return TRACEE_ERR;
		}
		return TRACEE_RUNNING;
	}

	// check for SW breakpoint
	bool found = false;
	breakpoint_t *bp = tracee->bp_list;
	while (bp) {
		if (bp->addr == regs.rip) {
			found = true;
			break;
		}

		bp = bp->next;
	}

	if (!found) {
		pr_debug("no breakpoint found for addr: %llx", regs.rip);
		pr_info_raw("tracee received signal: SIGTRAP\n");
		return TRACEE_STOPPED;
	}

	// rewind back to the previous instruction and resume
	if (_breakpoint_restore_original(tracee, &regs, bp->addr, bp->value) ==
	    -1) {
		pr_err("error in restoring original state to bp");
		return TRACEE_STOPPED;
	}

	// handle PLT bp
	if (bp->is_plt_bp) {
		// single step until GOT is changed;
		long got_val = bp->sym->got.val;
		long new_val = got_val;

		do {
			// single step
			DO_SINGLESTEP(tracee, TRACEE_ERR);

			new_val = ptrace(
			    PTRACE_PEEKDATA, tracee->pid, bp->sym->got.addr, 0);
			if (new_val == -1) {
				pr_err("error in getting new GOT value for plt "
				       "bp");
				return TRACEE_ERR;
			}
		} while (got_val == new_val);

		SYM_UPDATE_ADDR(bp->sym, new_val);
		pr_debug("GOT value changed for bp(%s), new_addr=%#llx",
		    bp->sym->name, bp->sym->addr);

		long new_data =
		    ptrace(PTRACE_PEEKDATA, tracee->pid, new_val, 0);
		if (new_data == -1) {
			pr_err("error in getting data at new addr in bp");
			return TRACEE_ERR;
		}

		pr_debug("new bp addr=%#lx, val=%#lx", new_val, new_data);
		bp->addr = new_val;
		bp->value = new_data;
		sym_sort_trigger();

		// single step till that address ?
		struct user_regs_struct r;
		if (ptrace(PTRACE_GETREGS, tracee->pid, NULL, &r) == -1) {
			pr_err("error in getting regs: %s", strerror(errno));
			return TRACEE_ERR;
		}

		pr_debug("rip_plt=%#llx", r.rip);

		while (r.rip != (unsigned long)new_val) {
			DO_SINGLESTEP(tracee, TRACEE_ERR);

			if (ptrace(PTRACE_GETREGS, tracee->pid, NULL, &r) ==
			    -1) {
				pr_err("error in getting regs: %s",
				    strerror(errno));
				return TRACEE_ERR;
			}
		}

		bp->is_plt_bp = false;
	}

	++bp->counter;
	tracee->pending_bp = bp;
	breakpoint_print(bp);
	return TRACEE_STOPPED;
}

void breakpoint_cleanup(tracee_t *tracee)
{
	pr_debug("breakpoint cleanup");
	breakpoint_t *bp = tracee->bp_list;
	breakpoint_t *t = NULL;
	while (bp != NULL) {
		t = bp;
		bp = bp->next;
		free(t);
	}
	tracee->bp_list = NULL;
}