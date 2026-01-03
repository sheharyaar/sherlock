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
	    (strcmp(sym1->name, sym2->name) == 0) &&                           \
	    (strcmp(sym1->file_name, sym2->file_name) == 0)

#define SHERLOCK_SYMBOL(sym, _base, _addr, _name, _file)                       \
	do {                                                                   \
		sym->base = _base;                                             \
		sym->addr = _addr;                                             \
		sym->name = _name;                                             \
		sym->file_name = _file;                                        \
	} while (0)

// TOOD: valgrind check and free other fields ?
#define SHERLOCK_SYMBOL_FREE(sym)                                              \
	do {                                                                   \
		if (sum != NULL) {                                             \
			free(sym)                                              \
		}                                                              \
	} while (0)

#endif
