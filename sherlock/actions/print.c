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

#define PRINT_REG(regs, target) pr_info_raw("%lld\n", regs.target);

#define PRINT_REG_ADDR(regs, target) pr_info_raw("%#llx\n", regs.target);

#define MATCH_REG(regs, reg, target)                                           \
	do {                                                                   \
		if (strncmp(reg, #target, strlen(#target)) == 0) {             \
			PRINT_REG(regs, target);                               \
			return;                                                \
		}                                                              \
	} while (0)

#define MATCH_REG_ADDR(regs, reg, target)                                      \
	do {                                                                   \
		if (strncmp(reg, #target, strlen(#target)) == 0) {             \
			PRINT_REG_ADDR(regs, target)                           \
			return;                                                \
		}                                                              \
	} while (0)

static void print_addr(tracee_t *tracee, char *addr)
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

static void print_reg(tracee_t *tracee, char *reg)
{
	struct user_regs_struct regs;
	if (ptrace(PTRACE_GETREGS, tracee->pid, NULL, &regs) == -1) {
		pr_err("error in getting registers");
		return;
	}

	MATCH_REG(regs, reg, cs);
	MATCH_REG(regs, reg, ds);
	MATCH_REG(regs, reg, es);
	MATCH_REG(regs, reg, fs);
	MATCH_REG(regs, reg, gs);
	MATCH_REG(regs, reg, ss);
	MATCH_REG(regs, reg, eflags);
	MATCH_REG(regs, reg, rax);
	MATCH_REG(regs, reg, rbx);
	MATCH_REG(regs, reg, rcx);
	MATCH_REG(regs, reg, rdx);
	MATCH_REG(regs, reg, rsi);
	MATCH_REG(regs, reg, rdi);
	MATCH_REG_ADDR(regs, reg, rsp);
	MATCH_REG_ADDR(regs, reg, rbp);
	MATCH_REG_ADDR(regs, reg, rip);
	MATCH_REG(regs, reg, r8);
	MATCH_REG(regs, reg, r9);
	MATCH_REG(regs, reg, r10);
	MATCH_REG(regs, reg, r11);
	MATCH_REG(regs, reg, r12);
	MATCH_REG(regs, reg, r13);
	MATCH_REG(regs, reg, r14);
	MATCH_REG(regs, reg, r15);
	pr_err("invalid register");
}

void print_regs(tracee_t *tracee)
{
	struct user_regs_struct regs;
	if (ptrace(PTRACE_GETREGS, tracee->pid, NULL, &regs) == -1) {
		pr_err("error in getting registers");
		return;
	}

	PRINT_REG(regs, cs);
	PRINT_REG(regs, ds);
	PRINT_REG(regs, es);
	PRINT_REG(regs, fs);
	PRINT_REG(regs, gs);
	PRINT_REG(regs, ss);
	PRINT_REG(regs, eflags);
	PRINT_REG(regs, rax);
	PRINT_REG(regs, rbx);
	PRINT_REG(regs, rcx);
	PRINT_REG(regs, rdx);
	PRINT_REG(regs, rsi);
	PRINT_REG(regs, rdi);
	PRINT_REG_ADDR(regs, rsp);
	PRINT_REG_ADDR(regs, rbp);
	PRINT_REG_ADDR(regs, rip);
	PRINT_REG(regs, r8);
	PRINT_REG(regs, r9);
	PRINT_REG(regs, r10);
	PRINT_REG(regs, r11);
	PRINT_REG(regs, r12);
	PRINT_REG(regs, r13);
	PRINT_REG(regs, r14);
	PRINT_REG(regs, r15);
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