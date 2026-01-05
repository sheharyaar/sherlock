/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "action_internal.h"
#include <sherlock/sym.h>
#include <sherlock/breakpoint.h>

static tracee_state_e info_addr(tracee_t *tracee, char *arg)
{
	unsigned long long addr = 0;
	ARG_TO_ULL(arg, addr);
	if (errno != 0) {
		pr_err("invalid address passed, only decimal/hex supported");
		return TRACEE_STOPPED;
	}

	// TODO: nearest symbol ??
	symbol_t *sym = sym_lookup_addr(tracee, addr);
	if (!sym) {
		pr_info_raw("no symbol matches %s\n", arg);
		return TRACEE_STOPPED;
	}

	if (addr == sym->addr)
		pr_info_raw("%s in section %s of %s\n", sym->name, "null",
		    sym->file_name);
	else
		pr_info_raw("%s + %lld in section %s of %s\n", sym->name,
		    (addr - sym->addr), "null", sym->file_name);

	return TRACEE_STOPPED;
}

static tracee_state_e info_func(tracee_t *tracee, char *func)
{
	// TODO: print function (symbol)
	// here we would require GOT resolution and memory map mapping
	symbol_t *sym = sym_lookup_name(tracee, func);
	if (sym == NULL) {
		pr_info_raw(
		    "the symbol '%s' is not present or loaded yet\n", func);
		return TRACEE_STOPPED;
	}

	pr_info_raw("symbol '%s' is at '%#llx' in %s\n", func, sym->addr,
	    sym->file_name);
	return TRACEE_STOPPED;
}

static tracee_state_e info_funcs(
    tracee_t *tracee, __attribute__((unused)) char *args)
{
	sym_printall(tracee);
	return TRACEE_STOPPED;
}

// gives info about registers, breakpoints, etc.
static tracee_state_e info_breakpoints(
    tracee_t *tracee, __attribute__((unused)) char *args)
{
	breakpoint_printall(tracee);
	return TRACEE_STOPPED;
}

static tracee_state_e info_regs(
    tracee_t *tracee, __attribute__((unused)) char *args)
{
	return action_handler_call(
	    tracee, ACTION_PRINT, ENTITY_REGISTER, "all");
}

static bool match_info(char *act)
{
	return (MATCH_STR(act, info) || MATCH_STR(act, inf));
}

static action_t action_info = { .type = ACTION_INFO,
	.ent_handler = {
	    [ENTITY_BREAKPOINT] = info_breakpoints,
	    [ENTITY_REGISTER] = info_regs,
		[ENTITY_FUNCTION] = info_func,
		[ENTITY_FUNCTIONS] = info_funcs,
		[ENTITY_ADDRESS] = info_addr,
	},
	.match_action = match_info,
	.name = "info"
};

REG_ACTION(info, &action_info);