/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#ifndef _SHERLOCK_ELF_H
#define _SHERLOCK_ELF_H

#include <sherlock/sherlock.h>

int elf_setup_syms(tracee_t *tracee);
int elf_sym_lookup(char *name, symbol_t ***sym_list);
void elf_sym_printall();
void elf_cleanup();

#endif