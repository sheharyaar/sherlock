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

static tracee_state_e watch_addr(tracee_t *tracee, char *arg)
{
	unsigned long long addr = 0;
	ARG_TO_ULL(arg, addr);
	if (addr == 0) {
		pr_err(
		    "invalid address passed, non-zero decimal/hex supported");
		return TRACEE_STOPPED;
	}

	if (watchpoint_add(tracee, addr, true) == -1) {
		pr_err("error in adding watchpoint");
		return TRACEE_STOPPED;
	}

	return TRACEE_STOPPED;
}

static bool match_watch(char *act)
{
	return (MATCH_STR(act, watch) || MATCH_STR(act, w));
}

static action_t action_watch = { .type = ACTION_WATCH,
	.ent_handler = {
		[ENTITY_ADDRESS] = watch_addr,
	},
	.match_action = match_watch,
	.name = "watch"
};

REG_ACTION(info, &action_watch);
