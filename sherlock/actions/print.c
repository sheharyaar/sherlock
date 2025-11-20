/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "../action.h"
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>

// TODO: ENTITY_VARIABLE,

#define MATCH_REG(reg, target)                                                 \
	do {                                                                   \
		if (strncmp(reg, #target, strlen(#target)) == 0) {             \
			pr_info_raw("%lld\n", regs.target);                    \
			return;                                                \
		}                                                              \
	} while (0)

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
	MATCH_REG(reg, rsp);
	MATCH_REG(reg, rbp);
	MATCH_REG(reg, rip);
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

	if (MATCH_ENTITY(entity, reg)) {
		print_reg(tracee, args);
		goto out;
	}

out:
	RET_ACTION(tracee, TRACEE_STOPPED);
}