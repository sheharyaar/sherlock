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

#define MATCH_STR(str, target) strncmp(str, #target, strlen(#target)) == 0

// TODO: Complete this
#define INIT_ENTITIES(...) \
	typedef enum ENTITY_E { __VA_ARGS__ } entity_e; \
	const char *entity_str[] = {#__VA_ARGS__};

INIT_ENTITIES(
	ENTITY_FUNCTION,
	ENTITY_VARIABLE,
	ENTITY_ADDRESS,
	ENTITY_LINE,
	ENTITY_FILE_LINE,
	ENTITY_REGISTER,
	ENTITY_BREAKPOINT,
	ENTITY_NONE, // entities not belonging to the other above
	ENTITY_COUNT
)

typedef enum ACTION_E {
	ACTION_RUN,
	ACTION_STEP,
	ACTION_NEXT,  // TODO
	ACTION_BREAK, // TODO
	ACTION_KILL,
	// information / inspection
	ACTION_PRINT,
	ACTION_SET,
	ACTION_INFO,
	ACTION_BACKTRACE,
	ACTION_EXAMINE,
	ACTION_WATCH,
	ACTION_THREAD,
	ACTION_THREAD_APPLY,
	ACTION_COUNT,
} action_e;

typedef tracee_state_e (*entity_handler_t)(tracee_t *tracee, char *args);

typedef struct ACTION_S {
	action_e type;
	entity_handler_t handler[ENTITY_COUNT];
	char *name;
} action_t;

// Used by action handlers to register themselves
int action_handler_reg(action_t *act);

// Used to call handler for a given entity and action, can be used by other
// handlers. Example: "info" can call "print" handlers to print the values.
tracee_state_e action_handler_call(
    tracee_t *t, action_e act, entity_e ent, char *args);

tracee_state_e action_parse_input(tracee_t *t, char *input);

#define REG_ACTION(action, act)                                                \
	__attribute__((constructor)) static void register_##action_handler(    \
	    void)                                                              \
	{                                                                      \
		if (action_handler_reg(act) == -1) {                           \
			pr_err("registering %s handler failed: %s", #action,   \
			    strerror(errno));                                  \
			return;                                                \
		}                                                              \
		pr_debug("registered %s handler successfully", #action);       \
	}

#endif
