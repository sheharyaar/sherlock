/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "../action.h"

// gives info about registers, breakpoints, etc.
static tracee_state_e info_breakpoints(tracee_t *tracee, char *args)
{
	breakpoint_t *bp = tracee->bp;
	while (bp) {
		pr_info_raw("[%d]: %#llx\n", bp->idx, bp->addr);
		pr_debug("value: %#lx\n", bp->value);
		bp = bp->next;
	}
	return TRACEE_STOPPED;
}

static tracee_state_e info_regs(tracee_t *tracee, char *args)
{
	return action_handler_call(
	    tracee, ACTION_PRINT, ENTITY_REGISTER, "all");
}

static action_t action_info = { .type = ACTION_INFO,
	.handler = {
	    [ENTITY_BREAKPOINT] = info_breakpoints,
	    [ENTITY_REGISTER] = info_regs,
	}, 
};

REG_ACTION(info, &action_info);