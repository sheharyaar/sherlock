/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#ifndef _SHERLOCK_H
#define _SHERLOCK_H

#include "log.h"
#include <unistd.h>

#define SHERLOCK_MAX_STRLEN 256

typedef struct BREAKPOINT {
	unsigned long long addr;
} breakpoint_t;

typedef struct TRACEE {
	pid_t pid;
	breakpoint_t *breakpoints;
	char name[SHERLOCK_MAX_STRLEN];
} tracee_t;

int tracee_setup_pid(tracee_t *tracee, int pid);
int tracee_setup_exec(tracee_t *tracee, char *argv[]);

#endif