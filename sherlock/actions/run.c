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

REG_ACTION(run)
{
	pr_debug("action: run");
	if (ptrace(PTRACE_CONT, tracee->pid, NULL, 0) == -1) {
		pr_err("error in ptrace: %s", strerror(errno));
		RET_ACTION(tracee, TRACEE_ERR);
	}

	RET_ACTION(tracee, TRACEE_RUNNING);
}