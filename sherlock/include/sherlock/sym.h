/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#ifndef _SHERLOCK_SYM_H
#define _SHERLOCK_SYM_H

#include <sherlock/sherlock.h>

#define SYM_UPDATE_ADDR(sym, res_addr)                                         \
	do {                                                                   \
		sym->addr = (unsigned long)res_addr;                           \
		mem_map_t *map = sym_proc_addr_map(sym->addr, sym->size);      \
		if (map != NULL) {                                             \
			sym->map = map;                                        \
			sym->base = map->start;                                \
			sym->file_name = map->path;                            \
		}                                                              \
                                                                               \
		section_t *section = sym_addr_section(sym->addr, sym->size);   \
		if (section) {                                                 \
			sym->section = section;                                \
		}                                                              \
	} while (0)

int sym_setup(tracee_t *tracee);
symbol_t *sym_lookup_name(tracee_t *tracee, char *name);
symbol_t *sym_lookup_addr(tracee_t *tracee, unsigned long long addr);
section_t *sym_addr_section(unsigned long long addr, unsigned long long size);
mem_map_t *sym_proc_addr_map(unsigned long long addr, unsigned long long size);
int sym_proc_map_setup(tracee_t *tracee);
int sym_proc_pid_info(tracee_t *tracee);
void sym_sort_trigger();
void sym_printall(tracee_t *tracee);
void sym_cleanup(tracee_t *tracee);

// r_debug related functions
int sym_setup_dldebug(tracee_t *tracee);
int sym_handle_dldbg_syms(tracee_t *tracee);

#endif