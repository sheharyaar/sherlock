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

typedef enum {
	// execution control
	ACTION_RUN,
	ACTION_CONTINUE,
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
	// number of actions, returned on erro
	ACTION_NONE,
} action_type;

typedef enum {
	ENTITY_FUNCTION,
	ENTITY_VARIABLE,
	ENTITY_ADDRESS,
	ENTITY_LINE,
	ENTITY_FILE_LINE,
	ENTITY_REGISTER,
} entity_type;

typedef struct TRACEE_ACTION {
	action_type type;
	entity_type entity;
	unsigned long long val;
} action_t;

#endif