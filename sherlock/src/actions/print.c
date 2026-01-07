/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#include "action_internal.h"
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>

// TODO_LATER: print ENTITY_VARIABLE

#define PRINT_REG(regs, target) pr_info_raw("%lld\n", regs.target);

#define PRINT_REG_ADDR(regs, target) pr_info_raw("%#llx\n", regs.target);

#define PRINT_REG_STR(regs, target)                                            \
	pr_info_raw("%s=%lld\n", #target, regs.target);

#define PRINT_REG_ADDR_STR(regs, target)                                       \
	pr_info_raw("%s=%#llx\n", #target, regs.target);

#define MATCH_REG(regs, reg, target)                                           \
	do {                                                                   \
		if (MATCH_STR(reg, target)) {                                  \
			PRINT_REG(regs, target);                               \
			return TRACEE_STOPPED;                                 \
		}                                                              \
	} while (0)

#define MATCH_REG_ADDR(regs, reg, target)                                      \
	do {                                                                   \
		if (MATCH_STR(reg, target)) {                                  \
			PRINT_REG_ADDR(regs, target)                           \
			return TRACEE_STOPPED;                                 \
		}                                                              \
	} while (0)

static tracee_state_e print_addr(tracee_t *tracee, char *addr)
{
	if (addr == NULL) {
		pr_err("invalid address passed");
		return TRACEE_STOPPED;
	}

	// need to check this later, since PEEK* can return -1 as the value
	unsigned long long raddr;
	ARG_TO_ULL(addr, raddr);
	if (raddr == 0) {
		pr_err("invalid address passed, only decimal/hex supported");
		return TRACEE_STOPPED;
	}

	long data = ptrace(PTRACE_PEEKDATA, tracee->pid, raddr, NULL);
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

		return TRACEE_STOPPED;
	}

	pr_info_raw("0x%016lx\n", data);
	return TRACEE_STOPPED;
}

static tracee_state_e print_regs(tracee_t *tracee)
{
	struct user_regs_struct regs;
	if (ptrace(PTRACE_GETREGS, tracee->pid, NULL, &regs) == -1) {
		pr_err("print_regs: error in getting registers: %s",
		    strerror(errno));
		return TRACEE_ERR;
	}

	PRINT_REG_STR(regs, cs);
	PRINT_REG_STR(regs, ds);
	PRINT_REG_STR(regs, es);
	PRINT_REG_STR(regs, fs);
	PRINT_REG_STR(regs, gs);
	PRINT_REG_STR(regs, ss);
	PRINT_REG_STR(regs, eflags);
	PRINT_REG_STR(regs, rax);
	PRINT_REG_STR(regs, rbx);
	PRINT_REG_STR(regs, rcx);
	PRINT_REG_STR(regs, rdx);
	PRINT_REG_STR(regs, rsi);
	PRINT_REG_STR(regs, rdi);
	PRINT_REG_ADDR_STR(regs, rsp);
	PRINT_REG_ADDR_STR(regs, rbp);
	PRINT_REG_ADDR_STR(regs, rip);
	PRINT_REG_STR(regs, r8);
	PRINT_REG_STR(regs, r9);
	PRINT_REG_STR(regs, r10);
	PRINT_REG_STR(regs, r11);
	PRINT_REG_STR(regs, r12);
	PRINT_REG_STR(regs, r13);
	PRINT_REG_STR(regs, r14);
	PRINT_REG_STR(regs, r15);
	return TRACEE_STOPPED;
}

static tracee_state_e print_reg(tracee_t *tracee, char *reg)
{
	if (MATCH_STR(reg, all)) {
		return print_regs(tracee);
	}

	struct user_regs_struct regs;
	if (ptrace(PTRACE_GETREGS, tracee->pid, NULL, &regs) == -1) {
		pr_err("print_reg: error in getting registers: %s",
		    strerror(errno));
		return TRACEE_ERR;
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
	pr_err("invalid register: %s", reg);
	return TRACEE_STOPPED;
}

static bool match_print(char *act)
{
	return (MATCH_STR(act, print) || MATCH_STR(act, p));
}

static action_t action_print = {
	.type = ACTION_PRINT,
	.ent_handler = {
		[ENTITY_REGISTER] = print_reg,
		[ENTITY_ADDRESS] = print_addr,
	},
	.match_action = match_print,
	.name = "print",
};

REG_ACTION(print, &action_print);