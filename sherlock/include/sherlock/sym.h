/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#ifndef _SHERLOCK_SYM_H
#define _SHERLOCK_SYM_H

#include <sherlock/sherlock.h>

int sym_setup(tracee_t *tracee);
int sym_lookup(char *name, symbol_t ***sym_list);
void sym_printall();
void sym_cleanup();

#endif