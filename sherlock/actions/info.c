/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "../action.h"
#include <stdlib.h>

// gives info about registers, breakpoints, etc.
REG_ACTION(info)
{
	if (entity == NULL) {
		pr_err("invalid args, usage: info <breaks|regs>");
		goto out;
	}

	if (MATCH_STR(entity, breaks)) {
		breakpoint_t *bp = tracee->bp;
		while (bp) {
			pr_info_raw("[%d]: %#llx\n", bp->idx, bp->addr);
			pr_debug("value: %#lx\n", bp->value);
			bp = bp->next;
		}
		goto out;
	}

	if (MATCH_STR(entity, regs)) {
		print_regs(tracee);
		goto out;
	}
out:
	RET_ACTION(tracee, TRACEE_STOPPED);
}