/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "log.h"
#include "sherlock.h"
#include "action.h"
#include <search.h>
#include <stdlib.h>
#include <string.h>

#define MATCH_CALL_ACTION(target)                                              \
	do {                                                                   \
		if (strncmp(#target, action, strlen(#target)) == 0)            \
			return target##_execute(tracee, entity, args);         \
	} while (0)

tracee_state_t action_parse_input(tracee_t *tracee, char *input)
{
	// remove the trailing \n;
	input[strlen(input)] = '\0';

	char *action = strtok(input, " ");
	if (action == NULL) {
		action = input;
	}

	char *entity = strtok(NULL, " ");
	char *args = strtok(NULL, " ");

	if (MATCH_STR(action, q) || MATCH_STR(action, quit)) {
		exit(0);
	}

	MATCH_CALL_ACTION(run);
	MATCH_CALL_ACTION(kill);
	MATCH_CALL_ACTION(step);
	MATCH_CALL_ACTION(print);
	MATCH_CALL_ACTION(break);
	MATCH_CALL_ACTION(info);

	pr_err("invalid input");
	// This is a special case where the debugger doesn't need to shut down
	// if invalid input is received.
	RET_ACTION(tracee, TRACEE_STOPPED);
}