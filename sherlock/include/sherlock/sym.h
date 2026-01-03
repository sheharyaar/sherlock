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
int sym_proc_map_setup(tracee_t *tracee);
int sym_proc_pid_info(tracee_t *tracee);
void sym_printall();
void sym_cleanup(tracee_t *tracee);

#endif