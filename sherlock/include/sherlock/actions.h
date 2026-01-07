/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#ifndef _SHERLOCK_ACTIONS_H
#define _SHERLOCK_ACTIONS_H

#include <sherlock/sherlock.h>

tracee_state_e action_parse_input(tracee_t *t, char *input);
void action_cleanup(tracee_t *tracee);

#endif