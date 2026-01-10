/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
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

#define SHERLOCK_SYMBOL(                                                       \
    _sym, _base, _addr, _gotaddr, _gotval, _sz, _name, _dyn, _res)             \
	do {                                                                   \
		_sym->base = _base;                                            \
		_sym->addr = _addr;                                            \
		_sym->got.addr = _gotaddr;                                     \
		_sym->got.val = _gotval;                                       \
		_sym->size = _sz;                                              \
		_sym->name = _name;                                            \
		_sym->file_name = NULL;                                        \
		_sym->dyn_sym = _dyn;                                          \
		_sym->needs_resolve = _res;                                    \
		_sym->section = NULL;                                          \
		_sym->map = NULL;                                              \
		_sym->bp = NULL;                                               \
                                                                               \
		/* get associated map */                                       \
		mem_map_t *map = sym_proc_addr_map(_sym->addr, _sym->size);    \
		if (map) {                                                     \
			_sym->map = map;                                       \
			_sym->file_name = map->path;                           \
		}                                                              \
                                                                               \
		section_t *section = sym_addr_section(_sym->addr, _sym->size); \
		if (section) {                                                 \
			_sym->section = section;                               \
		}                                                              \
                                                                               \
		HASH_ADD_KEYPTR(hh, sherlock_symtab, _sym->name,               \
		    strlen(_sym->name), _sym);                                 \
	} while (0)

#define SHERLOCK_SYMBOL_STATIC(_sym, _base, _addr, _size, _name)               \
	SHERLOCK_SYMBOL(                                                       \
	    _sym, _base, _addr, 0UL, 0UL, _size, _name, false, false)

#define SHERLOCK_SYMBOL_DYN(                                                   \
    _sym, _base, _addr, _got_addr, _got_val, _name, _res)                      \
	SHERLOCK_SYMBOL(                                                       \
	    _sym, _base, _addr, _got_addr, _got_val, 0UL, _name, true, _res)

void proc_cleanup(tracee_t *tracee);
int sym_resolve_dyn(tracee_t *tracee);

#endif
