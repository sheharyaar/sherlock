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

static tracee_state_e run(tracee_t *tracee, char *args)
{
	if (ptrace(PTRACE_CONT, tracee->pid, NULL, 0) == -1) {
		pr_err("error in ptrace: %s", strerror(errno));
		return TRACEE_ERR;
	}

	return TRACEE_RUNNING;
}

static bool match_run(char *act) { return MATCH_STR(act, run); }

static action_t action_run = { 
	.type = ACTION_RUN,
	.ent_handler = {
	    [ENTITY_NONE] = run,
	},
	.match_action = match_run,
	.name = "run"
};

REG_ACTION(run, &action_run);