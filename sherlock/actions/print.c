/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "../action.h"
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>

// TODO: print ENTITY_VARIABLE

#define MATCH_REG(reg, target)                                                 \
	do {                                                                   \
		if (strncmp(reg, #target, strlen(#target)) == 0) {             \
			pr_info_raw("%lld\n", regs.target);                    \
			return;                                                \
		}                                                              \
	} while (0)

#define MATCH_REG_ADDR(reg, target)                                            \
	do {                                                                   \
		if (strncmp(reg, #target, strlen(#target)) == 0) {             \
			pr_info_raw("%#llx\n", regs.target);                   \
			return;                                                \
		}                                                              \
	} while (0)

void print_addr(tracee_t *tracee, char *addr)
{
	if (addr == NULL) {
		pr_err("invalid address passed");
		return;
	}

	// need to check this later, since PEEK* can return -1 as the value
	bool hex = false;
	long data;
	unsigned long long raddr;

	// check for alphabets
	int i = 0;
	while (addr[i]) {
		if (isalpha(addr[i])) {
			hex = true;
			break;
		}
		i++;
	}

	int base = (hex) ? 16 : 10;
	errno = 0;
	raddr = strtoull(addr, NULL, base);
	if (errno != 0) {
		pr_err("invalid address passed, only decimal/hex supported");
		return;
	}

	data = ptrace(PTRACE_PEEKDATA, tracee->pid, raddr, NULL);
	if (data == -1 && errno != 0) {
		// some error occured
		if (errno == EIO || errno == EFAULT) {
			pr_info_raw("the requested memory address(%#llx) is "
				    "not accessible\n",
			    raddr);
		} else {
			pr_err("reading the address(%#llx) failed: %s", raddr,
			    strerror(errno));
		}

		return;
	}

	pr_info_raw("0x%016lx\n", data);
}

void print_reg(tracee_t *tracee, char *reg)
{
	struct user_regs_struct regs;
	if (ptrace(PTRACE_GETREGS, tracee->pid, NULL, &regs) == -1) {
		pr_err("error in getting registers");
		return;
	}

	MATCH_REG(reg, cs);
	MATCH_REG(reg, ds);
	MATCH_REG(reg, es);
	MATCH_REG(reg, fs);
	MATCH_REG(reg, gs);
	MATCH_REG(reg, ss);
	MATCH_REG(reg, eflags);
	MATCH_REG(reg, rax);
	MATCH_REG(reg, rbx);
	MATCH_REG(reg, rcx);
	MATCH_REG(reg, rdx);
	MATCH_REG(reg, rsi);
	MATCH_REG(reg, rdi);
	MATCH_REG_ADDR(reg, rsp);
	MATCH_REG_ADDR(reg, rbp);
	MATCH_REG_ADDR(reg, rip);
	MATCH_REG(reg, r8);
	MATCH_REG(reg, r9);
	MATCH_REG(reg, r10);
	MATCH_REG(reg, r11);
	MATCH_REG(reg, r12);
	MATCH_REG(reg, r13);
	MATCH_REG(reg, r14);
	MATCH_REG(reg, r15);
	pr_err("invalid register");
}

REG_ACTION(print)
{
	if (args == NULL) {
		pr_err("invalid input");
		goto out;
	}

	if (MATCH_STR(entity, reg)) {
		print_reg(tracee, args);
		goto out;
	}

	if (MATCH_STR(entity, addr)) {
		print_addr(tracee, args);
		goto out;
	}

	pr_info("invalid parameters");
out:
	RET_ACTION(tracee, TRACEE_STOPPED);
}