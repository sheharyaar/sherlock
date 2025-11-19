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

#define REG_ACTION(action) int action##_execute(tracee_t *tracee, char *input)
#define CALL_ACTION(action, tracee, input) action##_execute(tracee, input)
#define MATCH_ACTION(str, input) strncmp(str, input, strlen(str)) == 0

#define MATCH_CALL_ACTION(tracee, input, action)                               \
	do {                                                                   \
		if (MATCH_ACTION(#action, input))                              \
			return CALL_ACTION(action, tracee, input);             \
	} while (0)

#define RET_ACTION(tracee, ret)                                                \
	do {                                                                   \
		tracee->state = ret;                                           \
		return tracee->state;                                          \
	} while (0)

typedef enum {
	// execution control
	ACTION_RUN,
	ACTION_STEP,
	ACTION_NEXT,
	ACTION_BREAK,
	ACTION_KILL,
	// information / inspection
	ACTION_PRINT,
	ACTION_SET,
	ACTION_INFO,
	ACTION_BACKTRACE,
	ACTION_EXAMINE,
	ACTION_WATCH,
	// thread
	ACTION_THREAD,
	ACTION_THREAD_APPLY,
	// number of actions
	ACTION_COUNT,
} action_type;

typedef enum {
	ENTITY_FUNCTION,
	ENTITY_VARIABLE,
	ENTITY_ADDRESS,
	ENTITY_LINE,
	ENTITY_FILE_LINE,
	ENTITY_REGISTER,
	ENTITY_COUNT
} entity_type;

typedef struct TRACEE_ACTION {
	entity_type entity;
	unsigned long long val;
} action_t;

REG_ACTION(run);
REG_ACTION(kill);
REG_ACTION(step);

#endif