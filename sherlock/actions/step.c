/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "action.h"
#include <sys/ptrace.h>

static tracee_state_e step(tracee_t *tracee, __attribute__((unused)) char *args)
{
	if (ptrace(PTRACE_SINGLESTEP, tracee->pid, NULL, NULL) == -1) {
		pr_err("error in ptrace: %s", strerror(errno));
		return TRACEE_ERR;
	}
	return TRACEE_RUNNING;
}

static bool match_step(char *act)
{
	return (MATCH_STR(act, step) || MATCH_STR(act, s));
}

static action_t action_step = { 
	.type = ACTION_STEP,
	.ent_handler = {
	    [ENTITY_NONE] = step,
	},
	.match_action = match_step,
	.name = "step",
};

REG_ACTION(step, &action_step);