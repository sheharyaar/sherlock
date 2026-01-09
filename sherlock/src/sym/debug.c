/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#include <sherlock/sym.h>

int sym_setup_dldebug(tracee_t *tracee)
{
	if (tracee->debug.addr == 0) {
		pr_err("invalid address passed to sym_setup_dldebug");
		return -1;
	}

	pr_debug("DT_DEBUG address: %#lx", tracee->debug.addr);
	// TODO: Handle r_debug structure, insert software berakpoint here
	// and read link_map to update symbols.
	return 0;
}