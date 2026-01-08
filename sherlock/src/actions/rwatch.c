/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#include "action_internal.h"
#include <sherlock/breakpoint.h>

static tracee_state_e rwatch_addr(tracee_t *tracee, char *arg)
{
	unsigned long long addr = 0;
	ARG_TO_ULL(arg, addr);
	if (addr == 0) {
		pr_err(
		    "invalid address passed, non-zero decimal/hex supported");
		return TRACEE_STOPPED;
	}

	if (watchpoint_add(tracee, addr, false) == -1) {
		pr_err("error in adding watchpoint");
		return TRACEE_STOPPED;
	}

	return TRACEE_STOPPED;
}

static bool match_rwatch(char *act)
{
	return (MATCH_STR(act, rwatch) || MATCH_STR(act, rw));
}

static action_t action_rwatch = { .type = ACTION_RWATCH,
	.ent_handler = {
		[ENTITY_ADDRESS] = rwatch_addr,
	},
	.match_action = match_rwatch,
	.name = "rwatch"
};

REG_ACTION(info, &action_rwatch);
