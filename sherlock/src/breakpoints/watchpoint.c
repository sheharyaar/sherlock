/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#include <sherlock/breakpoint.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <byteswap.h>

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

#define DR_LOCAL_BIT(idx) (1ULL << ((idx) * 2))
#define DR_ON(dr7, idx) ((dr7) & DR_LOCAL_BIT(idx))
#define DR_SET_ON(dr7, idx) ((dr7) | DR_LOCAL_BIT(idx))

#define DR_RW_SHIFT(idx) (16 + (idx) * 4)
#define DR_LEN_SHIFT(idx) (18 + (idx) * 4)

#define DR_RW_MASK(idx) (0b11ULL << DR_RW_SHIFT(idx))
#define DR_LEN_MASK(idx) (0b11ULL << DR_LEN_SHIFT(idx))

#define DR_RW(dr7, idx) (((dr7) >> DR_RW_SHIFT(idx)) & 0b11)
#define DR_LEN(dr7, idx) (((dr7) >> DR_LEN_SHIFT(idx)) & 0b11)

#define DR_SET_RW(dr7, idx, rw)                                                \
	(((dr7) & ~DR_RW_MASK(idx)) | ((uint64_t)(rw) << DR_RW_SHIFT(idx)))

#define DR_SET_LEN(dr7, idx, len)                                              \
	(((dr7) & ~DR_LEN_MASK(idx)) | ((uint64_t)(len) << DR_LEN_SHIFT(idx)))

void watchpoint_printall(tracee_t *tracee)
{
	long data = 0UL;
	data = ptrace(PTRACE_PEEKUSER, tracee->pid, DR_OFFSET(DR_CTRL), NULL);
	if (data == -1) {
		pr_err("error in reading DR[7] reg: %s", strerror(errno));
		return;
	}

	pr_debug("[info] dr7=%#lx", data);

	// Check for L0-L3
	for (int i = 0; i <= 3; i++) {
		if (DR_ON(data, i)) {
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
			if (DR_RW(data, i) == 0b01) {
				rw = "W";
			} else if (DR_RW(data, i) == 0b11) {
				rw = "RW";
			} else {
				rw = "?";
			}

			int len = DR_LEN(data, i);
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

			pr_info_raw("[%d] address=%#lx, R/W=%s, Len=%d bytes\n",
			    i, dr_data, rw, len);
		}
	}
}

int watchpoint_add(tracee_t *tracee, unsigned long long addr, bool write_only)
{
	if (addr == 0) {
		pr_warn("invalid address passed to watchpoint_add");
		return -1;
	}

	// TODO: make it generic based on length
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
		if (!DR_ON(data, i)) {
			// enable the DR[i] bit
			long wp_dr7 = DR_SET_ON(data, i);
			// set RW[i] and LEN[i]
			wp_dr7 = DR_SET_LEN(wp_dr7, i, 0b11);
			if (write_only)
				wp_dr7 = DR_SET_RW(wp_dr7, i, 0b01);
			else
				wp_dr7 = DR_SET_RW(wp_dr7, i, 0b11);

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
