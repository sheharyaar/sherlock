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

/*
	TODO: ENTITY_VARIABLE,
	ENTITY_ADDRESS,
	ENTITY_REGISTER
*/

REG_ACTION(print)
{
	pr_debug("action: print");
	RET_ACTION(tracee, TRACEE_STOPPED);
}