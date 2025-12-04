/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "../action.h"
#include <signal.h>
#include <stdio.h>

static tracee_state_e kill_tracee(tracee_t *tracee, char *args)
{
	pr_info_raw("Do you really want to kill the tracee (Y / N): ");
	char opt[8];
	fgets(opt, 8, stdin);
	if (opt[0] == 'y' || opt[0] == 'Y') {
		kill(tracee->pid, SIGKILL);
		return TRACEE_KILLED;
	}

	return TRACEE_STOPPED;
}

static bool match_kill(char *act) { return MATCH_STR(act, kill); }

static action_t action_kill = { .type = ACTION_KILL,
	.ent_handler = { [ENTITY_NONE] = kill_tracee, },
	.match_action = match_kill,
	.name = "kill"
	};

REG_ACTION(kill, &action_kill);