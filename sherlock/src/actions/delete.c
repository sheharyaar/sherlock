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

static tracee_state_e delete_breakpoint(
    tracee_t *tracee, __attribute__((unused)) char *arg)
{
	errno = 0;
	unsigned int idx = strtoumax(arg, NULL, 10);
	if (idx == 0 || errno != 0) {
		pr_err("invalid breakpoint number passed");
		return TRACEE_STOPPED;
	}

	breakpoint_delete(tracee, idx);
	return TRACEE_STOPPED;
}

static tracee_state_e delete_watchpoint(
    tracee_t *tracee, __attribute__((unused)) char *arg)
{
	errno = 0;
	unsigned int idx = strtoumax(arg, NULL, 10);
	if (errno != 0) {
		pr_err("invalid breakpoint number passed");
		return TRACEE_STOPPED;
	}

	watchpoint_delete(tracee, idx);
	return TRACEE_STOPPED;
}

static bool match_delete(char *act)
{
	return (MATCH_STR(act, delete) || MATCH_STR(act, del));
}

static action_t action_delete = { .type = ACTION_DELETE,
	.ent_handler = {
	    [ENTITY_BREAKPOINT] = delete_breakpoint,
		[ENTITY_WATCHPOINT] = delete_watchpoint,
	},
	.match_action = match_delete,
	.name = "delete"
};

REG_ACTION(delete, &action_delete);