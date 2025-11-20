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

REG_ACTION(step)
{
	if (ptrace(PTRACE_SINGLESTEP, tracee->pid, NULL, NULL) == -1) {
		pr_err("error in ptrace: %s", strerror(errno));
		RET_ACTION(tracee, TRACEE_ERR);
	}
	RET_ACTION(tracee, TRACEE_RUNNING);
}