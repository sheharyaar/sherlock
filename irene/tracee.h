/*
 * Irene - Library call tracer
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
	// The plt start and end address is base + plt relative addr, like,
	// 0x555f23432 + 0x1020
	unsigned long long plt_start;
	unsigned long long plt_end;
	unsigned long long plt_entsize;
	unsigned long long va_base;
	unsigned long bp_replace;
	char file_name[256];
	pid_t pid;
	bool execd;
} tracee_t;

int tracee_setup(int argc, char *argv[], tracee_t *tracee);
int elf_plt_init(tracee_t *tracee);
int elf_mem_va_base(tracee_t *tracee);
char *elf_get_plt_name(tracee_t *tracee, unsigned long long addr);
int elf_break_plt_all(tracee_t *tracee);

#endif
