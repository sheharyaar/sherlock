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

static tracee_state_e info_funcs(__attribute__((unused)) tracee_t *tracee,
    __attribute__((unused)) char *args)
{
	sym_printall();
	return TRACEE_STOPPED;
}

// gives info about registers, breakpoints, etc.
static tracee_state_e info_breakpoints(
    tracee_t *tracee, __attribute__((unused)) char *args)
{
	breakpoint_printall(tracee);
	return TRACEE_STOPPED;
}

static tracee_state_e info_regs(
    tracee_t *tracee, __attribute__((unused)) char *args)
{
	return action_handler_call(
	    tracee, ACTION_PRINT, ENTITY_REGISTER, "all");
}

static bool match_info(char *act)
{
	return (MATCH_STR(act, info) || MATCH_STR(act, inf));
}

static action_t action_info = { .type = ACTION_INFO,
	.ent_handler = {
	    [ENTITY_BREAKPOINT] = info_breakpoints,
	    [ENTITY_REGISTER] = info_regs,
		[ENTITY_FUNCTION] = info_funcs,
	},
	.match_action = match_info,
	.name = "info"
};

REG_ACTION(info, &action_info);