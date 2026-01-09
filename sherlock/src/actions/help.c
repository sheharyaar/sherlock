/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#include "action_internal.h"

static tracee_state_e help_handler(
    __attribute__((unused)) tracee_t *tracee, char *args)
{
	if (args) {
		action_e act = (action_e)(intptr_t)args;
		if (act < 0 || act >= ACTION_COUNT) {
			pr_err("some error in printing help");
			return TRACEE_STOPPED;
		}

		action_print_call(act);
		return TRACEE_STOPPED;
	}

	print_actionsall();
	return TRACEE_STOPPED;
}

static void help_help()
{
	pr_info_raw("help,h\n");
	pr_info_raw("help,h <action>\n");
}

static bool match_help(char *act)
{
	return (MATCH_STR(act, help) || MATCH_STR(act, h));
}

static action_t action_help = { .type = ACTION_HELP,
	.ent_handler = {
	    [ENTITY_NONE] = help_handler,
	},
	.match_action = match_help,
	.help = help_help,
	.name = "help"
};

REG_ACTION(help, &action_help);