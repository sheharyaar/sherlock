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
#include "action.h"
#include <unistd.h>

#define SHERLOCK_MAX_STRLEN 256

typedef struct BREAKPOINT {
	unsigned long long addr;
} breakpoint_t;

typedef struct TRACEE {
	pid_t pid;
	breakpoint_t *breakpoints;
	unsigned long long va_base;
	char name[SHERLOCK_MAX_STRLEN];
} tracee_t;

int tracee_setup_pid(tracee_t *tracee, int pid);
int tracee_setup_exec(tracee_t *tracee, char *argv[]);

int elf_mem_va_base(tracee_t *tracee);

action_t *input_parse(char *input);

#endif