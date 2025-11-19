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

tracee_state_t action_parse_input(tracee_t *t, char *input)
{
	// TODO: Handle quit
	// if (MATCH_ACTION("q", input) || MATCH_ACTION("quit", input))
	// 	return DBG_ACTION_QUIT;

	MATCH_CALL_ACTION(t, input, run);
	MATCH_CALL_ACTION(t, input, kill);
	MATCH_CALL_ACTION(t, input, step);
	MATCH_CALL_ACTION(t, input, print);

	pr_err("invalid input");
	// This is a special case where the debugger doesn't need to shut down
	// if invalid input is received.
	RET_ACTION(t, TRACEE_STOPPED);
}