/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#define _GNU_SOURCE
#include "sym_internal.h"
#include <assert.h>
#include <errno.h>
#include <link.h>
#include <sherlock/sym.h>
#include <sherlock/breakpoint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

int sym_handle_dldbg_syms(tracee_t *tracee)
{
	struct iovec local[1];
	struct iovec remote[1];

	struct r_debug rdb;

	// the data will be stored here
	local[0].iov_base = &rdb;
	local[0].iov_len = sizeof(rdb);

	// the address in the tracee
	remote[0].iov_base = (void *)tracee->debug.r_debug_addr;
	remote[0].iov_len = sizeof(rdb);

	// read the state of the transfer
	if (process_vm_readv(tracee->pid, local, 1, remote, 1, 0) == -1) {
		pr_err("error in reading debug structure: %s", strerror(errno));
		return -1;
	}

	// these should be equal, if not equal either the read address was wrong
	// or initially the r_brk address was calculated wrong
	assert(rdb.r_brk == tracee->debug.r_brk_addr);

	pr_debug("rdb->state=%d", rdb.r_state);
	if (rdb.r_state != 0) {
		// changes are still happening
		return 0;
	}

	// update the symbol map by reading the GOTs
	if (sym_resolve_dyn(tracee) == -1) {
		pr_err("error in updating symbols after dl load");
		return -1;
	}

	return 0;
}

int sym_setup_dldebug(tracee_t *tracee)
{
	if (tracee->debug.r_debug_addr == 0) {
		pr_err("invalid address passed to sym_setup_dldebug");
		return -1;
	}

	pr_debug("DT_DEBUG address: %#lx", tracee->debug.r_debug_addr);

	unsigned long r_brk_addr =
	    tracee->debug.r_debug_addr + offsetof(struct r_debug, r_brk);
	pr_debug("r_brk addr=%#lx", r_brk_addr);

	if (r_brk_addr == 0) {
		pr_err("inavlid internal debug break address");
		return -1;
	}

	// read this address and check the data
	long r_brk_addr_data =
	    ptrace(PTRACE_PEEKTEXT, tracee->pid, r_brk_addr, 0);
	if (r_brk_addr_data == -1) {
		pr_err("error in reading r_brk_addr to add bp: %s",
		    strerror(errno));
		return -1;
	}

	tracee->debug.r_brk_addr = r_brk_addr_data;

	// add breakpoint to this addr
	if (breakpoint_add(tracee, r_brk_addr_data, NULL) == -1) {
		pr_err(
		    "error in adding breakpoint to internal linker structure");
		return -1;
	}

	return 0;
}