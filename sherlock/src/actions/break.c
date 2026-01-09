/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#include "action_internal.h"
#include <sherlock/sym.h>
#include <sherlock/breakpoint.h>
#include <sys/ptrace.h>
#include <stdlib.h>

/*
TODO [LATER]:
- File:line
- line
*/

static tracee_state_e breakpoint_addr(tracee_t *tracee, char *addr)
{
	errno = 0;
	// the address has to be in hex format
	unsigned long long bpaddr = 0;
	ARG_TO_ULL(addr, bpaddr);
	if (bpaddr == 0) {
		pr_err("invalid address passed");
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

	if (func == NULL || func[0] == '\0') {
		pr_err("invalid name to breakpoint");
		return TRACEE_STOPPED;
	}

	symbol_t *sym = sym_lookup_name(tracee, func);
	if (sym == NULL) {
		pr_info_raw("function '%s' is not yet defined.\n"
			    "Make breakpoint pending on future shared "
			    "library load? (y or [n]) ",
		    func);

		char inp;
		scanf("%c", &inp);
		if (inp != 'Y' && inp != 'y') {
			pr_info_raw("not adding breakpoint\n");
			return TRACEE_STOPPED;
		}

		// TODO [SYM_LATER]: yet to be implemented
		// TODO [SYM_LATER]: fix double >dbg prompt
		pr_warn("feature not implemented yet");
		return TRACEE_STOPPED;
	}

	func_addr = sym->addr;
	if (breakpoint_add(tracee, func_addr, sym) == -1)
		return TRACEE_ERR;

	return TRACEE_STOPPED;
}

static bool match_break(char *act)
{
	return (MATCH_STR(act, break) || MATCH_STR(act, br));
}

static void help_break()
{
	pr_info_raw("break,br func <function_name>\n");
	pr_info_raw("break,br addr <0xaddress>\n");
}

static action_t action_break = {
	.type = ACTION_BREAK,
	.ent_handler = { [ENTITY_ADDRESS] = breakpoint_addr,
	    [ENTITY_FUNCTION] = breakpoint_func },
	.match_action = match_break,
	.help = help_break,
	.name = "break",
};

REG_ACTION(breakpoint, &action_break);