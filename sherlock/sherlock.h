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

#include <unistd.h>

#define MAX_STR_LEN 256

typedef struct BREAKPOINT {
	unsigned long long addr;

} breakpoint_t;

typedef struct TRACEE {
	pid_t pid;
	breakpoint_t *breakpoints;
	char name[MAX_STR_LEN];
} tracee_t;

#endif