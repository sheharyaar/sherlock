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

#define SHERLOCK_SYMBOL_EQ(sym1, sym2)                                         \
	sym1->base == sym2->base && sym1->addr == sym2->addr &&                \
	    sym1->size == sym2->size &&                                        \
	    (strcmp(sym1->name, sym2->name) == 0) &&                           \
	    (strcmp(sym1->file_name, sym2->file_name) == 0)

#define SHERLOCK_SYMBOL(sym, _base, _addr, _size, _name, _file)                \
	do {                                                                   \
		sym->base = _base;                                             \
		sym->addr = _addr;                                             \
		sym->size = _size;                                             \
		sym->name = _name;                                             \
		sym->file_name = _file;                                        \
	} while (0)

void proc_cleanup(tracee_t *tracee);
mem_map_t *sym_proc_addr_map(unsigned long long addr);

#endif
