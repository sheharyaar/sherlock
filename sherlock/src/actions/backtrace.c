/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#include "action_internal.h"
#include <libunwind-ptrace.h>

static tracee_state_e backtrace(
    tracee_t *tracee, __attribute__((unused)) char *args)
{
	void *unw_context = _UPT_create(tracee->pid);
	unw_cursor_t unw_cursor;
	if (unw_init_remote(&unw_cursor, tracee->unw_addr, unw_context) != 0) {
		pr_err("cannot initialize cursor for remote unwinding\n");
		goto err;
	}

	do {
		unw_word_t offset, pc;
		char sym[4096];
		if (unw_get_reg(&unw_cursor, UNW_REG_IP, &pc)) {
			pr_err("ERROR: cannot read program counter\n");
			goto err;
		}

		pr_info_raw("0x%lx: ", pc);

		if (unw_get_proc_name(&unw_cursor, sym, sizeof(sym), &offset) ==
		    0)
			pr_info_raw("(%s+0x%lx)\n", sym, offset);
		else
			pr_info_raw("-- no symbol name found\n");
	} while (unw_step(&unw_cursor) > 0);

err:
	return TRACEE_STOPPED;
}

static bool match_backtrace(char *act)
{
	return (MATCH_STR(act, backtrace) || MATCH_STR(act, bt));
}

static void help_backtrace() { pr_info_raw("backtrace,bt\n"); }

static action_t action_backtrace = { 
	.type = ACTION_BACKTRACE,
	.ent_handler = {
	    [ENTITY_NONE] = backtrace,
	},
	.match_action = match_backtrace,
	.help = help_backtrace,
	.name = "backtrace"
};

REG_ACTION(run, &action_backtrace);