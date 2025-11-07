/*
 * Watson - System call tracer
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#ifndef _TRACE_H
#define _TRACE_H

#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <stdbool.h>

typedef enum state { UNATTACHED, ENTRY, EXIT } state_t;

typedef struct TRACEE {
	unsigned long long base;
	pid_t pid;
	bool execd;
} tracee_t;

#define tracee_continue_trace(mode)                                            \
	do {                                                                   \
		if (ptrace(mode, tracee.pid, NULL, 0) == -1) {                 \
			pr_err("ptrace cont err: %s", strerror(errno));        \
			goto err;                                              \
		}                                                              \
	} while (0)

#endif

#define CALL_TO_VA(rip, instr, base)                                           \
	(((rip) + 0x05 + (int)(((instr) & 0xffffffffffULL) >> 8)) - base)

void print_libs(char *file);