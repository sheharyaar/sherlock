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

REG_ACTION(kill)
{
	pr_info_raw("Do you really want to kill the tracee (Y / N): ");
	char opt[8];
	fgets(opt, 8, stdin);
	if (opt[0] == 'y' || opt[0] == 'Y') {
		kill(tracee->pid, SIGKILL);
		RET_ACTION(tracee, TRACEE_KILLED);
	}
	RET_ACTION(tracee, TRACEE_STOPPED);
}