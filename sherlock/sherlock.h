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
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <libunwind-ptrace.h>

#define SHERLOCK_MAX_STRLEN 256

typedef enum {
	TRACEE_INIT,
	TRACEE_RUNNING,
	TRACEE_STOPPED,
	TRACEE_KILLED,
	TRACEE_ERR
} tracee_state_e;

typedef struct SYMBOL {
	// addr = va_base + rel_addr
	unsigned long long addr;
	// if base == 0, then the symbol is dynamic and not yet loaded
	unsigned long long base;
	const char *name;
	const char *file_name;
	struct SYMBOL *next;
} symbol_t;

typedef struct BREAKPOINT {
	unsigned long long addr;
	long value;
	symbol_t *sym;
	struct BREAKPOINT *next;
	unsigned int idx;
} breakpoint_t;

typedef struct TRACEE {
	pid_t pid;
	breakpoint_t *bp;
	unsigned long long va_base;
	unw_addr_space_t unw_addr;
	void *unw_context;
	unw_cursor_t unw_cursor;
	char name[SHERLOCK_MAX_STRLEN];
	char exe_path[SHERLOCK_MAX_STRLEN];
} tracee_t;

int tracee_setup_pid(tracee_t *tracee, int pid);
int tracee_setup_exec(tracee_t *tracee, char *argv[]);

int elf_setup_syms(tracee_t *tracee);
int elf_mem_va_base(tracee_t *tracee);
int elf_sym_lookup(char *name, symbol_t ***sym_list);

#endif
