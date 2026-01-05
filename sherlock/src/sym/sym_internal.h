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

#define SHERLOCK_SYMBOL(                                                       \
    sym, _base, _addr, _size, _name, _file, _is_dyn, _plt_patch)               \
	do {                                                                   \
		sym->base = _base;                                             \
		sym->addr = _addr;                                             \
		sym->res_base = 0;                                             \
		sym->res_addr = 0;                                             \
		sym->size = _size;                                             \
		sym->name = _name;                                             \
		sym->file_name = _file;                                        \
		sym->dyn_sym = _is_dyn;                                        \
		sym->plt_patch = _plt_patch;                                   \
		sym->map = NULL;                                               \
                                                                               \
		/* get associated map */                                       \
		mem_map_t *map =                                               \
		    sym_proc_addr_map(new_sym->addr, new_sym->size);           \
		if (map != NULL) {                                             \
			new_sym->map = map;                                    \
			new_sym->file_name = map->path;                        \
		}                                                              \
                                                                               \
		HASH_ADD_KEYPTR(hh, sherlock_symtab, new_sym->name,            \
		    strlen(new_sym->name), new_sym);                           \
	} while (0)

#define SHERLOCK_SYMBOL_STATIC(sym, _base, _addr, _size, _name, _file)         \
	SHERLOCK_SYMBOL(sym, _base, _addr, _size, _name, _file, false, false)

#define SHERLOCK_SYMBOL_DYN(sym, _base, _addr, _name, _plt_patch)              \
	SHERLOCK_SYMBOL(sym, _base, _addr, 0UL, _name, NULL, true, _plt_patch)

void proc_cleanup(tracee_t *tracee);
mem_map_t *sym_proc_addr_map(unsigned long long addr, unsigned long long size);

#endif
