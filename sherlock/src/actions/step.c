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
#include <sys/ptrace.h>

static tracee_state_e step(tracee_t *tracee, __attribute__((unused)) char *args)
{
	if (tracee->pending_bp) {
		if (breakpoint_pending(tracee) == -1) {
			pr_err(
			    "error when running tracee (breakpoint_pending)");
			return TRACEE_ERR;
		}
	}

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

static void help_step() { pr_info_raw("step,s\n"); }

static action_t action_step = { 
	.type = ACTION_STEP,
	.ent_handler = {
	    [ENTITY_NONE] = step,
	},
	.match_action = match_step,
	.help = help_step,
	.name = "step",
};

REG_ACTION(step, &action_step);