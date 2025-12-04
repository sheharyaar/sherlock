/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "../action.h"
#include <stdlib.h>

/*
TODO:
- Function name
- Address
- File:line
- Conditional ?

* List of breakpoints
* Ability to add / remove breakpoints
* Use INT to add breakpoint -- maybe first implement it in ltrace, compare
performance and then port to debugger.
*/

static tracee_state_e breakpoint_add(
    tracee_t *tracee, unsigned long long bpaddr, unsigned long bpvalue)
{
	breakpoint_t *bp = (breakpoint_t *)calloc(1, sizeof(breakpoint_t));
	if (bp == NULL) {
		pr_err("breakpoint_add: cannot allocate breakpoint");
		return TRACEE_ERR;
	}

	bp->addr = bpaddr;
	bp->value = bpvalue;
	bp->idx = 0;
	if (tracee->bp) {
		bp->idx = tracee->bp->idx + 1;
	}
	bp->next = tracee->bp;
	tracee->bp = bp;

	unsigned long val = (bpvalue & 0xFFFFFFFFFFFFFF00UL) | 0xCCUL;
	if (ptrace(PTRACE_POKETEXT, tracee->pid, bpaddr, val) == -1) {
		pr_err("breakpoint_add: error in PTRACE_POKETEXT- %s",
		    strerror(errno));
		return TRACEE_ERR;
	}

	return TRACEE_STOPPED;
}

static tracee_state_e breakpoint_addr(tracee_t *tracee, char *addr)
{
	errno = 0;
	// the address has to be in hex format
	unsigned long long bpaddr = strtoull(addr, NULL, 16);
	if (errno != 0) {
		pr_err("invalid address passed, only hex supported");
		return TRACEE_STOPPED;
	}

	pr_debug("breaking address: %#llx", bpaddr);
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
		return TRACEE_STOPPED;
	}

	pr_debug("instruction at address(%#llx): %#lx", bpaddr, (data & 0xFF));
	return breakpoint_add(tracee, bpaddr, data);
}

static bool match_break(char *act)
{
	return (MATCH_STR(act, break) || MATCH_STR(act, br));
}

static action_t action_break = {
	.type = ACTION_BREAK,
	.ent_handler = {[ENTITY_ADDRESS] = breakpoint_addr,},
	.match_action = match_break,
	.name = "break",
};

REG_ACTION(breakpoint, &action_break);