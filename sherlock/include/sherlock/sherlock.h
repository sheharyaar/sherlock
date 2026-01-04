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

#include <sherlock/log.h>
#include <libunwind-ptrace.h>
#include <stdbool.h>

#define SHERLOCK_MAX_STRLEN 256

typedef enum {
	TRACEE_INIT,
	TRACEE_RUNNING,
	TRACEE_STOPPED,
	TRACEE_KILLED,
	TRACEE_ERR
} tracee_state_e;

typedef enum ENTITY_E {
	ENTITY_FUNCTION,
	ENTITY_VARIABLE,
	ENTITY_ADDRESS,
	ENTITY_LINE,
	ENTITY_FILE_LINE,
	ENTITY_REGISTER,
	ENTITY_BREAKPOINT,
	ENTITY_NONE, // entities not belonging to the other above
	ENTITY_COUNT
} entity_e;

typedef enum ACTION_E {
	ACTION_RUN,
	ACTION_STEP,
	ACTION_NEXT,
	ACTION_BREAK,
	ACTION_KILL,
	// information / inspection
	ACTION_PRINT,
	ACTION_SET,
	ACTION_INFO,
	ACTION_BACKTRACE,
	ACTION_EXAMINE,
	ACTION_WATCH,
	ACTION_THREAD,
	ACTION_THREAD_APPLY,
	ACTION_COUNT,
} action_e;

typedef struct SYMBOL {
	// addr = va_base + rel_addr
	unsigned long long addr;
	// if base == 0, then the symbol is dynamic and not yet loaded
	unsigned long long base;
	const char *name;
	const char *file_name;
	struct SYMBOL *next;
	bool need_plt_resolve;
} symbol_t;

typedef struct BREAKPOINT {
	unsigned long long addr;
	long value;
	symbol_t *sym;
	struct BREAKPOINT *next;
	unsigned int idx;
	unsigned int counter;
} breakpoint_t;

typedef struct MEM_MAP {
	unsigned long long start;
	unsigned long long end;
	char path[SHERLOCK_MAX_STRLEN];
} mem_map_t;

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

#endif