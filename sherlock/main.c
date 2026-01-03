/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#define _GNU_SOURCE
#include "log.h"
#include "sherlock.h"
#include "actions/action.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define dbg_prompt(str, count)                                                 \
	do {                                                                   \
		memset(str, 0, count);                                         \
		fprintf(stdout, DBG_PREFIX);                                   \
		fgets(str, count, stdin);                                      \
	} while (0)

static tracee_t global_tracee = {
	.bp = NULL,
	.exe_path = { 0 },
	.name = { 0 },
	.pid = 0,
	.unw_addr = 0,
	.unw_context = 0,
	.va_base = 0,
};

static pid_t sherlock_pid = 0;

static void exit_handler(void)
{
	pr_info("triggering exit handler");
	elf_cleanup();

	if (global_tracee.unw_context != NULL)
		_UPT_destroy(global_tracee.unw_context);

	if (global_tracee.unw_addr)
		unw_destroy_addr_space(global_tracee.unw_addr);
}

static void __attribute__((noreturn)) print_help_exit(int status)
{
	pr_info_raw("Usage:\n");
	pr_info_raw("$ sudo sherlock --pid PID\n");
	pr_info_raw("$ sherlock --exec program [args]\n");
	pr_info_raw("In cases where both --pid and --exec are present, --pid "
		    "will be used\n");
	exit(status);
}

static void signal_handler(int signal)
{
	if (signal == SIGINT) {
		if (global_tracee.pid != 0) {
			kill(global_tracee.pid, SIGINT);
		} else {
			exit(1);
		}
	} else {
		exit(0);
	}
}

// Sets up tracee and brings it to a stopped state.
// Returns -1 on failure.
static int setup(int argc, char *argv[], tracee_t *tracee)
{
	if (argc < 3)
		print_help_exit(1);

	if (strcmp("--help", argv[1]) == 0) {
		print_help_exit(0);
	}

	if (strcmp("--pid", argv[1]) == 0) {
		int pid = atoi(argv[2]);
		if (pid == 0 || pid < 0) {
			pr_err("invalid PID passed");
			return -1;
		}

		return tracee_setup_pid(tracee, pid);
	}

	if (strcmp("--exec", argv[1]) == 0) {
		return tracee_setup_exec(tracee, &argv[2]);
	}

	pr_err("invalid usage");
	print_help_exit(1);
}

static int setup_libunwind(tracee_t *tracee)
{
	tracee->unw_addr = unw_create_addr_space(&_UPT_accessors, 0);
	tracee->unw_context = _UPT_create(tracee->pid);
	if (unw_init_remote(&tracee->unw_cursor, tracee->unw_addr,
		tracee->unw_context) != 0) {
		pr_err("cannot initialize cursor for remote unwinding\n");
		return -1;
	}

	return 0;
}

// TOOD: Make the brealpoint permanent
static void breakpoint_handle(tracee_t *tracee)
{
	struct user_regs_struct regs;
	if (ptrace(PTRACE_GETREGS, tracee->pid, NULL, &regs) == -1) {
		pr_err("breakpoint_handle: error in getting registers: %s",
		    strerror(errno));
		return;
	}

	bool found = false;
	breakpoint_t *bp = tracee->bp;
	while (bp) {
		if (bp->addr + 1 == regs.rip) {
			found = true;
			break;
		}

		bp = bp->next;
	}

	// replace the change text and reset the rip
	if (found) {
		++bp->counter;
		if (bp->sym != NULL) {
			symbol_t *sym = bp->sym;
			pr_info_raw("Breakpoint %d, '%s' () at %#llx in %s\n",
			    bp->idx, sym->name, sym->addr,
			    sym->file_name == NULL ? "??" : sym->file_name);
		} else {
			pr_info_raw(
			    "Breakpoint %d, %#llx\n", bp->idx, bp->addr);
		}
		unsigned long val = bp->value;
		if (ptrace(PTRACE_POKETEXT, tracee->pid, bp->addr, val) == -1) {
			pr_err("breakpoint_handle: ptrace POKETEXT err - %s",
			    strerror(errno));
			return;
		}

		regs.rip -= 1;
		if (ptrace(PTRACE_SETREGS, tracee->pid, NULL, &regs) == -1) {
			pr_err("breakpoint_handle: ptrace SETREGS error - %s",
			    strerror(errno));
			return;
		}

		// single step and reset
		if (ptrace(PTRACE_SINGLESTEP, tracee->pid, NULL, NULL) == -1) {
			pr_err("error in breakpoint singleste: %s",
			    strerror(errno));
			return;
		}

		int wstatus = 0;
		if (waitpid(tracee->pid, &wstatus, 0) < 0) {
			pr_err("waitpid err: %s", strerror(errno));
			return;
		}

		if (!WIFSTOPPED(wstatus)) {
			pr_err("not stopped by SIGSTOP");
			return;
		}

		// restore the breakpoint
		val = (bp->value & 0xFFFFFFFFFFFFFF00UL) | 0xCCUL;
		if (ptrace(PTRACE_POKETEXT, tracee->pid, bp->addr, val) == -1) {
			pr_err(
			    "breakpoint_handle: error in PTRACE_POKETEXT- %s",
			    strerror(errno));
			return;
		}
	}
}

// TODO: Add signal handler to send SIGINT to tracee instead of debugger

int main(int argc, char *argv[])
{
	if (atexit(exit_handler) != 0) {
		pr_err("error in setting up exit handler");
		return 1;
	}

	if (setup(argc, argv, &global_tracee) == -1) {
		pr_err("error in setting up the tracee");
		return 1;
	}

	if (setup_libunwind(&global_tracee) == -1) {
		pr_err("setting up libunwind failed");
		return 1;
	}

	if (elf_setup_syms(&global_tracee) == -1) {
		pr_err("elf symbol parsing failed");
		goto cleanup_unw;
	}

	sherlock_pid = getpid();

	if (signal(SIGINT, signal_handler) == SIG_ERR) {
		pr_err("error in signal(SIGINT): %s", strerror(errno));
		goto cleanup_unw;
	}

	if (signal(SIGTERM, signal_handler) == SIG_ERR) {
		pr_err("error in signal(SIGTERM): %s", strerror(errno));
		goto cleanup_unw;
	}

	// TODO: Fix pgid and tty ownership
	// if (setpgid(0, 0) == -1) {
	// 	pr_err("error in parent setpgid: %s", strerror(errno));
	// 	return 1;
	// }

	char input[SHERLOCK_MAX_STRLEN];
	tracee_state_e state;

	/*
	Each action/input requires the tracee to be in stopped state. Initially,
	either through --exec or through --pid, the tracee is in stopped state.

	So the actions can be divided into two types: one that leave the tracee
	in stopped state and the others that restart the tracee.

	Actions that restart the tracee: run, step, next.
	Actions that leave it in the stopped state: all actions other than the
	above.
	 */
	int wstatus = 0;
	while (1) {
		dbg_prompt(input, SHERLOCK_MAX_STRLEN);
		state = action_parse_input(&global_tracee, input);
		if (state == TRACEE_ERR) {
			pr_err("critical error, killing debugger");
			goto cleanup_unw;
		}

		if (state == TRACEE_KILLED) {
			pr_info("the tracee has been killed, exiting debugger");
			goto cleanup_unw;
		}

#if DEBUG
		assert(state == TRACEE_RUNNING || state == TRACEE_STOPPED);
#endif

		if (state == TRACEE_RUNNING) {
			if (waitpid(global_tracee.pid, &wstatus, 0) < 0) {
				pr_err("waitpid err: %s", strerror(errno));
				goto cleanup_unw;
			}

			if (WIFSTOPPED(wstatus)) {
				if (WSTOPSIG(wstatus) == SIGTRAP) {
					// could be a breakpoint stop
					breakpoint_handle(&global_tracee);
				} else {
					pr_info_raw(
					    "tracee received signal: %s\n",
					    strsignal(WSTOPSIG(wstatus)));
				}
			}

			state = TRACEE_STOPPED;
		}
	}

	return 0;

cleanup_unw:
	unw_destroy_addr_space(global_tracee.unw_addr);
	_UPT_destroy(global_tracee.unw_context);
	return 1;
}
