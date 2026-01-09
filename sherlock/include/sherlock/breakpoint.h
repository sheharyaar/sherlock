/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#ifndef _SHERLOCK_BREAKPOINT_H
#define _SHERLOCK_BREAKPOINT_H

#include <sherlock/sherlock.h>

int breakpoint_add(tracee_t *tracee, unsigned long long bpaddr, symbol_t *sym);
int breakpoint_resume(tracee_t *tracee);
int breakpoint_handle(tracee_t *tracee);
void breakpoint_printall(tracee_t *tracee);
void breakpoint_delete(tracee_t *tracee, unsigned int idx);
void breakpoint_cleanup(tracee_t *tracee);

// Watch points
int watchpoint_add(tracee_t *tracee, unsigned long long addr, bool write_only);
// returns true if a watchpoint was found and prints the watchpoint detail
bool watchpoint_check_print(tracee_t *tracee);
void watchpoint_delete(tracee_t *tracee, unsigned int idx);
void watchpoint_printall(tracee_t *tracee);

#endif