/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#ifndef _SHERLOCK_INTERNAL_H
#define _SHERLOCK_INTERNAL_H

#include <sherlock/sherlock.h>

int tracee_setup_pid(tracee_t *tracee, int pid);
int tracee_setup_exec(tracee_t *tracee, char *argv[]);
void tracee_cleanup(tracee_t *tracee);

#endif