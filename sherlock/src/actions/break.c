/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "action_internal.h"
#include <sherlock/sym.h>
#include <sherlock/breakpoint.h>
#include <sys/ptrace.h>
#include <stdlib.h>

/*
TODO:
- File:line
- line
*/

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
	if (breakpoint_add(tracee, bpaddr, NULL) == -1)
		return TRACEE_ERR;

	return TRACEE_STOPPED;
}

static tracee_state_e breakpoint_func(tracee_t *tracee, char *func)
{
	// do a symbol lookup;
	unsigned long long func_addr = 0;
	symbol_t **sym_list = NULL;
	symbol_t *sym = NULL;

	int count = sym_lookup(func, &sym_list);
	if (count == -1) {
		pr_err("error in symbol lookup");
		return TRACEE_STOPPED;
	}

	if (count == 0) {
		pr_info_raw("function '%s' is not yet defined.\n"
			    "Make breakpoint pending on future shared "
			    "library load? (y or [n]) ",
		    func);

		char inp;
		scanf("%c", &inp);
		if (inp != 'Y' && inp != 'y') {
			pr_info_raw("not adding breakpoint\n");
			goto err_list;
		}

		// TODO: yet to be implemented
		// TOOD: fix double >dbg prompt
		pr_warn("feature not implemented yet");
		goto err_list;
	}

	// only one symbol (no conflicts)
	if (count == 1) {
		sym = sym_list[0];
		goto call_add;
	}

	pr_info_raw("The function matches the following symbols:\n");
	for (int i = 0; i < count; i++) {
		pr_info_raw("[%d] addr=%llx", i, sym_list[i]->addr);
	}
	pr_info_raw("Enter the index for which you want to "
		    "select the breakpoint: ");

	int input = -1;
	scanf("%d", &input);
	if (input < 0 || input >= count) {
		pr_info_raw("invalid index selected, skipping");
		goto err_list;
	}
	sym = sym_list[input];

call_add:
	func_addr = sym->addr;
	free(sym_list);
	if (breakpoint_add(tracee, func_addr, sym) == -1)
		return TRACEE_ERR;

	return TRACEE_STOPPED;

err_list:
	free(sym_list);
	return TRACEE_STOPPED;
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