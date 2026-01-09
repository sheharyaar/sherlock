/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#include "action_internal.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static const char *entity_str[ENTITY_COUNT] = {
	[ENTITY_FUNCTION] = "func",
	[ENTITY_FUNCTIONS] = "funcs",
	[ENTITY_VARIABLE] = "var",
	[ENTITY_ADDRESS] = "addr",
	[ENTITY_LINE] = "line",
	[ENTITY_FILE_LINE] = "fline",
	[ENTITY_REGISTER] = "reg",
	[ENTITY_BREAKPOINT] = "break",
	[ENTITY_WATCHPOINT] = "watch",
	[ENTITY_NONE] = "<none>",
};

// list of all action handlers
static action_t *action_list[ACTION_COUNT] = { 0 };

static action_e str_to_action(char *act_str)
{
	if (act_str == NULL) {
		pr_err("action is NULL");
		return ACTION_COUNT;
	}

	for (int act = 0; act < ACTION_COUNT; act++) {
		if (action_list[act] != NULL &&
		    action_list[act]->match_action != NULL &&
		    action_list[act]->match_action(act_str)) {
			return act;
		}
	}

	return ACTION_COUNT;
}

static entity_e str_to_entity(char *ent_str)
{
	if (ent_str == NULL) {
		return ENTITY_NONE;
	}

	for (int ent = 0; ent < ENTITY_NONE; ent++) {
		if (strcmp(ent_str, entity_str[ent]) == 0) {
			return ent;
		}
	}

	return ENTITY_COUNT;
}

void print_actionsall()
{
	pr_info_raw("Supported commands are: \n");
	for (int act = 0; act < ACTION_COUNT; act++) {
		if (action_list[act] != NULL) {
			action_list[act]->help();
		}
	}
}

static void print_supported_actions()
{
	pr_info_raw("Supported actions are: ");
	for (int act = 0; act < ACTION_COUNT; act++) {
		if (action_list[act] != NULL) {
			pr_info_raw("%s ", action_list[act]->name);
		}
	}
	pr_info_raw("\n");
}

void action_print_call(action_e act)
{
	if (act == ACTION_COUNT) {
		pr_err("action_print_call: invalid action passed");
		return;
	}

	pr_info_raw("Supported commands are: \n");
	action_list[act]->help();
}

int action_handler_reg(action_t *act)
{
	if (act == NULL) {
		ERR_RET_MSG(EINVAL, "passed arg 'act' is NULL");
	}

	if (act->type >= ACTION_COUNT) {
		ERR_RET_MSG(EINVAL, "invalid act->type(%d)", act->type);
	}

	if (action_list[act->type] != NULL) {
		ERR_RET_MSG(
		    EEXIST, "handler for (%s) already exists", act->name);
	}

	action_list[act->type] = act;
	return 0;
}

tracee_state_e action_handler_call(
    tracee_t *t, action_e act, entity_e ent, char *args)
{
	if (action_list[act] == NULL) {
		pr_err("invalid action(%d) requested", act);
		return TRACEE_STOPPED;
	}

	// here both act and ent are valid, so can just print their names
	if (action_list[act]->ent_handler[ent] == NULL) {
		pr_err("invalid entity(%s) for action(%s) requested",
		    entity_str[ent], action_list[act]->name);
		action_print_call(act);
		return TRACEE_STOPPED;
	}

	return action_list[act]->ent_handler[ent](t, args);
}

tracee_state_e action_parse_input(tracee_t *tracee, char *input)
{
	// remove the trailing \n;
	input[strlen(input) - 1] = '\0';

	char *action = strtok(input, " ");
	if (action == NULL) {
		action = input;
	}

	char *entity = strtok(NULL, " ");
	char *args = strtok(NULL, " ");

	if (MATCH_STR(action, q) || MATCH_STR(action, quit)) {
		exit(0);
	}

	// break into action and entity
	if (action[0] == '\0') {
		return TRACEE_STOPPED;
	}

	action_e act = str_to_action(action);
	if (act == ACTION_COUNT) {
		pr_err("invalid action: '%s'", action);
		print_supported_actions();
		return TRACEE_STOPPED;
	}

	if (act == ACTION_HELP) {
		if (entity == NULL) {
			return action_handler_call(
			    tracee, act, ENTITY_NONE, NULL);
		}

		int help_act = str_to_action(entity);
		if (help_act == ACTION_COUNT) {
			pr_err("invalid arg to help: '%s'", entity);
			action_print_call(act);
			return TRACEE_STOPPED;
		}

		return action_handler_call(
		    tracee, act, ENTITY_NONE, (char *)(intptr_t)help_act);
	}

	entity_e ent = str_to_entity(entity);
	if (ent == ENTITY_COUNT) {
		pr_err("invalid entity: '%s'", entity);
		action_print_call(act);
		return TRACEE_STOPPED;
	}

	return action_handler_call(tracee, act, ent, args);
}

void action_cleanup(__attribute__((unused)) tracee_t *tracee)
{
	pr_debug("action cleanup");
}