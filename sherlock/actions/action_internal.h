/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#ifndef _SHERLOCK_ACTION_INTERNAL_H
#define _SHERLOCK_ACTION_INTERNAL_H

#include <sherlock/actions.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

// Not using strncmp here, as I want to match the complete string, not the pref

#define UNKNOWN_ADDR_STR "??"
#define MATCH_STR(str_var, str) strcmp(str_var, #str) == 0

typedef tracee_state_e (*handler_entity_t)(tracee_t *tracee, char *args);
typedef bool (*handler_match_t)(char *act);

typedef struct ACTION_S {
	action_e type;
	handler_entity_t ent_handler[ENTITY_COUNT];
	handler_match_t match_action;
	const char *name;
} action_t;

// Used by action handlers to register themselves
int action_handler_reg(action_t *act);

// Used to call handler for a given entity and action, can be used by other
// handlers. Example: "info" can call "print" handlers to print the values.
tracee_state_e action_handler_call(
    tracee_t *t, action_e act, entity_e ent, char *args);

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
