/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#ifndef _ACTION_H
#define _ACTION_H

#include "sherlock.h"
#include <errno.h>
#include <string.h>

#define REG_ACTION(action)                                                     \
	int action##_execute(tracee_t *tracee, char *entity, char *args)

#define RET_ACTION(tracee, ret)                                                \
	do {                                                                   \
		tracee->state = ret;                                           \
		return tracee->state;                                          \
	} while (0)

#define MATCH_STR(str, target) strncmp(str, #target, strlen(#target)) == 0

/*
Actions:
	// execution control
	ACTION_RUN,
	ACTION_STEP,
	ACTION_NEXT,  // TODO
	ACTION_BREAK, // TODO
	ACTION_KILL,
	// information / inspection
	ACTION_PRINT,
	ACTION_SET,	  // TODO
	ACTION_INFO,	  // TODO
	ACTION_BACKTRACE, // TODO
	ACTION_EXAMINE,	  // TODO
	ACTION_WATCH,	  // TODO
	// thread
	ACTION_THREAD,	     // TODO
	ACTION_THREAD_APPLY, // TODO

entities:
	ENTITY_FUNCTION,
	ENTITY_VARIABLE,
	ENTITY_ADDRESS,
	ENTITY_LINE,
	ENTITY_FILE_LINE,
	ENTITY_REGISTER,
	ENTITY_BREAKPOINT,
*/

REG_ACTION(run);
REG_ACTION(kill);
REG_ACTION(step);
REG_ACTION(print);
REG_ACTION(break);
REG_ACTION(info);

void print_regs(tracee_t *tracee);

#endif