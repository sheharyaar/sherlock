/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025-26 Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>
 *
 * This file is licensed under the MIT License.
 */

#define _GNU_SOURCE
#include "sherlock_internal.h"
#include <assert.h>
#include <errno.h>
#include <sherlock/actions.h>
#include <sherlock/breakpoint.h>
#include <sherlock/sym.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>

#define dbg_prompt(str, count)                                                 \
	do {                                                                   \
		memset(str, 0, count);                                         \
		fprintf(stdout, DBG_PREFIX);                                   \
		fgets(str, count, stdin);                                      \
	} while (0)

static tracee_t global_tracee = {
	.bp_list = NULL,
	.exe_path = { 0 },
	.name = { 0 },
	.pid = 0,
	.unw_addr = NULL,
	.va_base = 0,
	.pending_bp = NULL,
};

static pid_t sherlock_pid = 0;

static void exit_handler(void)
{
	pr_info("triggering exit handler");
	// breakpoint_cleanup(&global_tracee);
	breakpoint_cleanup(&global_tracee);
	sym_cleanup(&global_tracee);
	action_cleanup(&global_tracee);
	tracee_cleanup(&global_tracee);
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
	return 0;
}

// TODO_LATER: Add signal handler to send SIGINT to tracee instead of debugger

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

	if (sym_setup(&global_tracee) == -1) {
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

	// TODO_LATER: Fix pgid and tty ownership
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

			if (WIFEXITED(wstatus)) {
				pr_info("tracee exited");
				return 0;
			}

			if (WIFSTOPPED(wstatus)) {
				if (WSTOPSIG(wstatus) == SIGTRAP) {
					// could be a breakpoint stop
					siginfo_t si;
					bool single_step = true;
					if (ptrace(PTRACE_GETSIGINFO,
						global_tracee.pid, NULL,
						&si) == -1) {
						pr_warn("ptrace_getsiginfo "
							"failed, sending it to "
							"breakpoint path: %s",
						    strerror(errno));
					}

					single_step = si.si_code == TRAP_TRACE;
					if (!single_step) {
						// TODO: check for watchpoint
						// stops
						if (breakpoint_handle(
							&global_tracee) == -1) {
							pr_err(
							    "error in handling "
							    "SIGTRAP");
						}
					}
				} else {
					pr_info_raw(
					    "tracee received signal: %s\n",
					    strsignal(WSTOPSIG(wstatus)));
				} /* SIGTRAP if-block*/
			} /* WIFSTOPPED if-block */

			state = TRACEE_STOPPED;
		}
	}

	return 0;

cleanup_unw:
	if (global_tracee.unw_addr != NULL) {
		unw_destroy_addr_space(global_tracee.unw_addr);
		global_tracee.unw_addr = NULL;
	}
	return 1;
}
