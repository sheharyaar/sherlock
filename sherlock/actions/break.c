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
- File:line
- line
*/

static tracee_state_e breakpoint_add(tracee_t *tracee,
    unsigned long long bpaddr, unsigned long bpvalue, char *name)
{
	breakpoint_t *bp = (breakpoint_t *)calloc(1, sizeof(breakpoint_t));
	if (bp == NULL) {
		pr_err("breakpoint_add: cannot allocate breakpoint");
		return TRACEE_ERR;
	}

	bp->addr = bpaddr;
	bp->value = bpvalue;
	bp->idx = 0;
	bp->name = name;
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

	pr_info_raw("Breakpoint %d added at address=%#llx\n", bp->idx, bpaddr);
	return TRACEE_STOPPED;
}

static tracee_state_e __breakpoint_addr(
    tracee_t *tracee, unsigned long long bpaddr, char *name)
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
		return TRACEE_STOPPED;
	}

	pr_debug("instruction at address(%#llx): %#lx", bpaddr, (data & 0xFF));
	return breakpoint_add(tracee, bpaddr, data, name);
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
	return __breakpoint_addr(tracee, bpaddr, UNKNOWN_ADDR_STR);
}

static tracee_state_e breakpoint_func(tracee_t *tracee, char *func)
{
	// do a symbol lookup;
	unsigned long long func_addr = 0;
	symbol_t **sym_list = NULL;
	char *name = NULL;

	int count = elf_sym_lookup(func, &sym_list);
	if (count == -1) {
		pr_err("error in symbol lookup");
		return TRACEE_STOPPED;
	}

	if (count == 1) {
		func_addr = sym_list[0]->addr;
		name = sym_list[0]->name;
		free(sym_list);
		return __breakpoint_addr(tracee, func_addr, name);
	}

	pr_info_raw("The function matches the following symbols:\n");
	for (int i = 0; i < count; i++) {
		pr_info_raw("[%d] addr=%llx", i, sym_list[i]->addr);
	}
	pr_info_raw(
	    "Enter the index for which you want to select the breakpoint: ");

	int input = -1;
	scanf("%d", &input);
	if (input < 0 || input >= count) {
		pr_info_raw("invalid index selected, skipping");
		free(sym_list);
		return TRACEE_STOPPED;
	}

	func_addr = sym_list[input]->addr;
	name = sym_list[input]->name;
	free(sym_list);
	return __breakpoint_addr(tracee, func_addr, name);
}

static bool match_break(char *act)
{
	return (MATCH_STR(act, break) || MATCH_STR(act, br));
}

static action_t action_break = {
	.type = ACTION_BREAK,
	.ent_handler = { [ENTITY_ADDRESS] = breakpoint_addr,
	    [ENTITY_FUNCTION] = breakpoint_func },
	.match_action = match_break,
	.name = "break",
};

REG_ACTION(breakpoint, &action_break);