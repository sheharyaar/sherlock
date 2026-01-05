/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#ifndef _SHERLOCK_SYM_INTERNAL_H
#define _SHERLOCK_SYM_INTERNAL_H

#include <sherlock/sym.h>
#include <string.h>
#include <errno.h>
#include <libelf.h>
#include <gelf.h>
#include <stdlib.h>

#define MATCH_STR(str_var, str) strcmp(str_var, #str) == 0

#define SHERLOCK_SYMBOL(_sym, _base, _addr, _size, _name, _is_dyn, _plt_patch) \
	do {                                                                   \
		_sym->base = _base;                                            \
		_sym->addr = _addr;                                            \
		_sym->res_base = 0;                                            \
		_sym->res_addr = 0;                                            \
		_sym->size = _size;                                            \
		_sym->name = _name;                                            \
		_sym->file_name = NULL;                                        \
		_sym->dyn_sym = _is_dyn;                                       \
		_sym->plt_patch = _plt_patch;                                  \
		_sym->section = NULL;                                          \
		_sym->map = NULL;                                              \
                                                                               \
		/* get associated map */                                       \
		mem_map_t *map = sym_proc_addr_map(_sym->addr, _sym->size);    \
		if (map != NULL) {                                             \
			_sym->map = map;                                       \
			_sym->file_name = map->path;                           \
		} else {                                                       \
			pr_warn("map for symbol(%s) is NULL", _sym->name);     \
			free(_sym);                                            \
			return -1;                                             \
		}                                                              \
                                                                               \
		section_t *section = sym_addr_section(_sym->addr, _sym->size); \
		if (!section) {                                                \
			pr_err("section not found for symbol(%s)", name);      \
			free(_sym);                                            \
			return -1;                                             \
		} else {                                                       \
			_sym->section = section;                               \
		}                                                              \
                                                                               \
		HASH_ADD_KEYPTR(hh, sherlock_symtab, _sym->name,               \
		    strlen(_sym->name), _sym);                                 \
	} while (0)

#define SHERLOCK_SYMBOL_STATIC(_sym, _base, _addr, _size, _name)               \
	SHERLOCK_SYMBOL(_sym, _base, _addr, _size, _name, false, false)

#define SHERLOCK_SYMBOL_DYN(_sym, _base, _addr, _name, _plt_patch)             \
	SHERLOCK_SYMBOL(_sym, _base, _addr, 0UL, _name, true, _plt_patch)

void proc_cleanup(tracee_t *tracee);
mem_map_t *sym_proc_addr_map(unsigned long long addr, unsigned long long size);

#endif
