/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#include <sherlock/breakpoint.h>
#include <sherlock/sym.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <byteswap.h>

// This is 4 as we only consider x86-64 for the debugger.
long watchpoint_old_values[4] = { 0 };

/*
 * DR4-DR5 should _not_ be used by software
 * DR6 status regsiter, relevant bits:
 *  - B0-B3 (0-3) [check which DR register caused the breakpoint]
 * DR7 control register, relevant bits:
 *  - L0(0), L1(2), L2(4), L3(6) [enable local hardware breakpoints]
 *  - R/W0, LEN0 (16-17, 18-19)
 *  - R/W1, LEN1 (20-21, 22-23)
 *  - R/W2, LEN2 (24-25, 26-27)
 *  - R/W3, LEN3 (28-29, 30-31)
 */

#define DR_OFFSET(idx) (offsetof(struct user, u_debugreg) + idx * sizeof(long))

#define DR_STATUS 6
#define DR_CTRL 7

#define DR7_LOCAL_BIT(idx) (1ULL << ((idx) * 2))
#define DR7_ON(dr7, idx) ((dr7) & DR7_LOCAL_BIT(idx))
#define DR7_SET_ON(dr7, idx) ((dr7) | DR7_LOCAL_BIT(idx))
#define DR7_SET_CLEAR(dr7, idx) ((dr7) & ~(DR7_LOCAL_BIT(idx)))

#define DR7_RW_SHIFT(idx) (16 + (idx) * 4)
#define DR7_LEN_SHIFT(idx) (18 + (idx) * 4)

#define DR7_RW_MASK(idx) (0b11ULL << DR7_RW_SHIFT(idx))
#define DR7_LEN_MASK(idx) (0b11ULL << DR7_LEN_SHIFT(idx))

#define DR7_RW(dr7, idx) (((dr7) >> DR7_RW_SHIFT(idx)) & 0b11)
#define DR7_LEN(dr7, idx) (((dr7) >> DR7_LEN_SHIFT(idx)) & 0b11)

#define DR7_RW_SET(dr7, idx, rw)                                               \
	(((dr7) & ~DR7_RW_MASK(idx)) | ((uint64_t)(rw) << DR7_RW_SHIFT(idx)))

#define DR7_LEN_SET(dr7, idx, len)                                             \
	(((dr7) & ~DR7_LEN_MASK(idx)) | ((uint64_t)(len) << DR7_LEN_SHIFT(idx)))

#define DR7_RW_CLEAR(dr7, idx)                                                 \
	(((dr7) & ~DR7_RW_MASK(idx)) & ~(0b11 << DR7_RW_SHIFT(idx)))

#define DR7_LEN_CLEAR(dr7, idx)                                                \
	(((dr7) & ~DR7_LEN_MASK(idx)) & ~(0b11 << DR7_LEN_SHIFT(idx)))

void watchpoint_delete(tracee_t *tracee, unsigned int idx)
{
	if (idx > 4) {
		return;
	}

	watchpoint_old_values[idx] = 0;

	long dr7_data = 0UL;
	dr7_data =
	    ptrace(PTRACE_PEEKUSER, tracee->pid, DR_OFFSET(DR_CTRL), NULL);
	if (dr7_data == -1) {
		pr_err("error in reading DR[7] reg: %s", strerror(errno));
		return;
	}

	if (DR7_ON(dr7_data, idx)) {
		// clear the DR7 bit for this index
		pr_debug("curr dr7=%#lx, idx_remove=%d", dr7_data, idx);
		dr7_data = DR7_LEN_CLEAR(dr7_data, idx);
		dr7_data = DR7_RW_CLEAR(dr7_data, idx);
		dr7_data = DR7_SET_CLEAR(dr7_data, idx);
		pr_debug("new dr7=%#lx", dr7_data);

		if (ptrace(PTRACE_POKEUSER, tracee->pid, DR_OFFSET(DR_CTRL),
			dr7_data) == -1) {
			pr_err(
			    "error in writing DR[7] reg: %s", strerror(errno));
			return;
		}

		long clear_data = 0UL;
		// clear DR[idx] reg
		if (ptrace(PTRACE_POKEUSER, tracee->pid, DR_OFFSET(idx),
			clear_data) == -1) {
			pr_err("wp_delete: error in writing DR[%d] reg: %s",
			    idx, strerror(errno));
			return;
		}
	}
}

void watchpoint_printall(tracee_t *tracee)
{
	// TODO [WP_LEN]: print depending on len of watchpoint
	long data = 0UL;
	data = ptrace(PTRACE_PEEKUSER, tracee->pid, DR_OFFSET(DR_CTRL), NULL);
	if (data == -1) {
		pr_err("error in reading DR[7] reg: %s", strerror(errno));
		return;
	}

	pr_debug("[info] dr7=%#lx", data);

	// Check for L0-L3
	for (int i = 0; i <= 3; i++) {
		if (DR7_ON(data, i)) {
			// get the watchpoint address and type
			long dr_data = 0UL;
			dr_data = ptrace(
			    PTRACE_PEEKUSER, tracee->pid, DR_OFFSET(i), NULL);
			if (dr_data == -1) {
				pr_err("error in reading DR[%d] reg: %s", i,
				    strerror(errno));
				return;
			}

			const char *rw = NULL;
			if (DR7_RW(data, i) == 0b01) {
				rw = "W";
			} else if (DR7_RW(data, i) == 0b11) {
				rw = "RW";
			} else {
				rw = "?";
			}

			int len = DR7_LEN(data, i);
			if (len == 0b00) {
				len = 1;
			} else if (len == 0b01) {
				len = 2;
			} else if (len == 0b10) {
				len = 8;
			} else if (len == 0b11) {
				len = 4;
			} else {
				len = 1;
			}

			pr_info_raw("[%d] address=%#lx, R/W=%s, Len=%d, "
				    "old_val=%3lx bytes\n",
			    i, dr_data, rw, len, watchpoint_old_values[i]);
		}
	}
}

// returns index of wp
int watchpoint_check(tracee_t *tracee, long *dst_addr, long *dst_data)
{
	// TODO [WP_LEN]: print depending on len of watchpoint
	long data = 0UL;
	data = ptrace(PTRACE_PEEKUSER, tracee->pid, DR_OFFSET(DR_STATUS), NULL);
	if (data == -1) {
		pr_err("error in reading DR[6] reg: %s", strerror(errno));
		return false;
	}

	if ((data & (0xf)) == 0) {
		// not a watchpoint stop
		pr_warn("unkown watchpoint");
		return -1;
	}

	// trailing zeros will give the index
	int idx = __builtin_ctz(data);
	pr_debug("watchpoint found at idx=%d", idx);

	long addr = ptrace(PTRACE_PEEKUSER, tracee->pid, DR_OFFSET(idx), NULL);
	if (addr == -1) {
		pr_err("error in getting DR[%d] register: %s", idx,
		    strerror(errno));
		return -1;
	}

	// print the watchpoint
	long new_val = ptrace(PTRACE_PEEKDATA, tracee->pid, addr, NULL);
	if (new_val == -1 && errno != 0) {
		if (errno == EIO || errno == EFAULT) {
			pr_info_raw("the requested memory address(%#lx) is "
				    "not accessible\n",
			    addr);
		} else {
			pr_err("reading the address(%#lx) failed: %s", addr,
			    strerror(errno));
		}

		*dst_addr = addr;
		return -1;
	}

	*dst_addr = addr;
	*dst_data = new_val;
	return idx;
}

#define DLDEBUG_WATCH_ADDR(tracee, addr)                                       \
	tracee->debug.need_watch &&                                            \
	    (unsigned long)addr == tracee->debug.r_debug_addr

tracee_state_e watchpoint_handle(tracee_t *tracee)
{
	// get the checkpoint address
	long addr = 0, new_val = 0;
	int idx = watchpoint_check(tracee, &addr, &new_val);
	if (idx == -1) {
		if (DLDEBUG_WATCH_ADDR(tracee, addr)) {
			tracee->debug.need_watch = false;
			tracee->debug.r_debug_addr = 0UL;
			pr_warn(
			    "some issue occured with linker debugger "
			    "interaction, symbol debugging _may_ get affected");
			return TRACEE_RUNNING;
		}

		pr_err("error in checking watchpoint");
		return TRACEE_STOPPED;
	}

	// handle this address only if starting (need watch)
	if (DLDEBUG_WATCH_ADDR(tracee, addr)) {
		tracee->debug.need_watch = false;
		tracee->debug.r_debug_addr =
		    new_val; // in failure we avoid this feat
		if (sym_setup_dldebug(tracee) == -1) {
			pr_warn(
			    "some issue occured with linker debugger "
			    "interaction, symbol debugging _may_ get affected");
		}

		// remove the watchpoint
		watchpoint_delete(tracee, idx);

		// resume the process
		if (ptrace(PTRACE_CONT, tracee->pid, NULL, 0) == -1) {
			pr_err("error in resuming tracee: %s", strerror(errno));
			return TRACEE_STOPPED;
		}

		return TRACEE_RUNNING;
	}

	struct user_regs_struct regs;
	if (ptrace(PTRACE_GETREGS, tracee->pid, NULL, &regs) == -1) {
		pr_err("watchpoint_check_print: error in getting registers: %s",
		    strerror(errno));
		return TRACEE_STOPPED;
	}

	// TODO [WP_URG]: is the r/w instruction RIP ? Or one instr before RIP ?
	pr_info_raw(
	    "Watchpoint %d, old_val=%#lx, new_val=%#lx, rw_instr = %#llx\n",
	    idx, watchpoint_old_values[idx], new_val, regs.rip);

	watchpoint_old_values[idx] = new_val;
	return TRACEE_STOPPED;
}

int watchpoint_add(tracee_t *tracee, unsigned long long addr, bool write_only)
{
	if (addr == 0) {
		pr_warn("invalid address passed to watchpoint_add");
		return -1;
	}

	// TODO [WP_LEN]: make it generic based on length
	// probably add it to the argument list
	if ((addr % 4) != 0) {
		pr_info_raw("address must be 4-byte aligned\n");
		return 0;
	}

	long data = 0UL;
	data = ptrace(PTRACE_PEEKUSER, tracee->pid, DR_OFFSET(DR_CTRL), NULL);
	if (data == -1) {
		pr_err("error in reading DR[7] reg: %s", strerror(errno));
		return -1;
	}

	// Check for L0-L3
	for (int i = 0; i <= 3; i++) {
		if (!DR7_ON(data, i)) {
			// fetch old value
			long old_val =
			    ptrace(PTRACE_PEEKDATA, tracee->pid, addr, NULL);
			if (old_val == -1 && errno != 0) {
				if (errno == EIO || errno == EFAULT) {
					pr_info_raw("the requested memory "
						    "address(%#llx) is "
						    "not accessible\n",
					    addr);
				} else {
					pr_err("reading the address(%#llx) "
					       "failed: %s",
					    addr, strerror(errno));
				}
				return -1;
			} else {
				watchpoint_old_values[i] = old_val;
			}

			// add the watchpoint
			// enable the DR[i] bit
			long wp_dr7 = DR7_SET_ON(data, i);
			// set RW[i] and LEN[i]
			wp_dr7 = DR7_LEN_SET(wp_dr7, i, 0b11);
			if (write_only)
				wp_dr7 = DR7_RW_SET(wp_dr7, i, 0b01);
			else
				wp_dr7 = DR7_RW_SET(wp_dr7, i, 0b11);

			pr_debug("DR[%d] writing dr7=%#lx", i, wp_dr7);

			long wp_addr = addr;
			if (ptrace(PTRACE_POKEUSER, tracee->pid, DR_OFFSET(i),
				wp_addr) == -1) {
				pr_err("unable to write DR[%d]: %s", i,
				    strerror(errno));
				return -1;
			}

			if (ptrace(PTRACE_POKEUSER, tracee->pid,
				DR_OFFSET(DR_CTRL), wp_dr7) == -1) {
				pr_err("unable to write to DR7: %s",
				    strerror(errno));
				return -1;
			}

			return 0;
		}
		pr_debug("DR[%d] already enabled", i);
	}

	pr_info_raw("cannot add more watchpoint/hardware breakpoints\n");
	return 0;
}
