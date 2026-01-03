/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#ifndef _SHERLOCK_INTERNAL_H
#define _SHERLOCK_INTERNAL_H

#include <sherlock/sherlock.h>

int tracee_setup_pid(tracee_t *tracee, int pid);
int tracee_setup_exec(tracee_t *tracee, char *argv[]);

#endif