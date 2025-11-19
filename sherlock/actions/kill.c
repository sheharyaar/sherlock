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

REG_ACTION(kill)
{
	pr_debug("action: kill");
	kill(tracee->pid, SIGKILL);
	RET_ACTION(tracee, TRACEE_KILLED);
}