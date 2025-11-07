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
	unsigned long long va_base;
	pid_t pid;
	bool execd;
} tracee_t;

#define CALL_TO_VA(rip, instr, base)                                           \
	(((rip) + 0x05 + (int)(((instr) & 0xffffffffffULL) >> 8)) - base)

void setup(int argc, char *argv[], tracee_t *tracee);
void print_libs(char *file);
int get_mem_va_base(tracee_t *tracee);

#endif
