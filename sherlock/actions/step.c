/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "../action.h"
#include <sys/ptrace.h>

static tracee_state_e step(tracee_t *tracee, char *args)
{
	if (ptrace(PTRACE_SINGLESTEP, tracee->pid, NULL, NULL) == -1) {
		pr_err("error in ptrace: %s", strerror(errno));
		return TRACEE_ERR;
	}
	return TRACEE_RUNNING;
}

static action_t action_step = { 
	.type = ACTION_STEP,
	.handler = {
	    [ENTITY_NONE] = step,
	},
};

REG_ACTION(step, &action_step);