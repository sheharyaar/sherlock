/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#ifndef _SHERLOCK_H
#define _SHERLOCK_H

#include <sherlock/log.h>
#include <libunwind-ptrace.h>
#include <stdbool.h>
#include <sherlock/uthash.h>

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
	ENTITY_FUNCTIONS,
	ENTITY_VARIABLE,
	ENTITY_ADDRESS,
	ENTITY_LINE,
	ENTITY_FILE_LINE,
	ENTITY_REGISTER,
	ENTITY_BREAKPOINT,
	ENTITY_WATCHPOINT,
	ENTITY_NONE, // entities not belonging to the other above
	ENTITY_COUNT
} entity_e;

typedef enum ACTION_E {
	ACTION_RUN,
	ACTION_STEP,
	ACTION_BREAK,
	ACTION_KILL,
	// information / inspection
	ACTION_PRINT,
	ACTION_INFO,
	ACTION_BACKTRACE,
	ACTION_WATCH,
	ACTION_RWATCH,
	ACTION_DELETE,
	ACTION_HELP,
	ACTION_COUNT,
} action_e;

typedef struct SECTION_MAP {
	unsigned long long start;
	unsigned long long end;
	const char *name;
} section_t;

typedef struct MEM_MAP {
	unsigned long long start;
	unsigned long long end;
	char path[SHERLOCK_MAX_STRLEN];
} mem_map_t;

typedef struct BREAKPOINT breakpoint_t;

typedef struct SYMBOL {
	// (elf) addr = va_base + rel_addr + rel_addend
	unsigned long long addr;
	unsigned long long base;
	struct GOT {
		unsigned long long addr;
		unsigned long long val;
	} got;
	unsigned long long size;
	const char *name;
	const char *file_name;
	section_t *section;
	mem_map_t *map;
	breakpoint_t *bp;
	UT_hash_handle hh;
	bool dyn_sym;
	// why seperate bool ? Once plt sym are upgraded to normal syms, we need
	// to have a @plt sym too, which does not need to be resolved but must
	// just be there, eg. puts gets resolved, then we have two symbols, puts
	// and puts@plt.
	bool needs_resolve;
	// TODO [SYM_DUP]: duplicate symbols can cause incorrect PEEKTEXT,
	// POKETEXT
} symbol_t;

typedef struct BREAKPOINT {
	unsigned long long addr;
	long value;
	symbol_t *sym;
	struct BREAKPOINT *next;
	unsigned int idx;
	unsigned int counter;
	bool is_plt_bp;
} breakpoint_t;

typedef struct TRACEE {
	pid_t pid;
	breakpoint_t *bp_list;
	breakpoint_t *pending_bp;
	unsigned long long va_base;
	unw_addr_space_t unw_addr;
	char name[SHERLOCK_MAX_STRLEN];
	char exe_path[SHERLOCK_MAX_STRLEN];
	struct _DEBUG {
		unsigned long r_debug_addr;
		unsigned long r_brk_addr;
		unsigned long r_brk_val;
		bool need_watch;
	} debug;
} tracee_t;

#endif