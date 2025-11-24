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
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define dbg_prompt(str, count)                                                 \
	do {                                                                   \
		memset(str, 0, count);                                         \
		fprintf(stdout, DBG_PREFIX);                                   \
		fgets(str, count, stdin);                                      \
	} while (0)

static tracee_t global_tracee = {
	.pid = 0,
	.bp = NULL,
	.va_base = 0,
	.name[0] = '\0',
	.state = -1,
};

static pid_t sherlock_pid = 0;

void __attribute__((noreturn)) print_help_exit(int status)
{
	pr_info_raw("Usage:\n");
	pr_info_raw("$ sudo sherlock --pid PID\n");
	pr_info_raw("$ sherlock --exec program [args]\n");
	pr_info_raw("In cases where both --pid and --exec are present, --pid "
		    "will be used\n");
	exit(status);
}

void signal_handler(int signal)
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
int setup(int argc, char *argv[], tracee_t *tracee)
{
	if (argc < 3)
		print_help_exit(1);

	if (strncmp("--help", argv[1], 6) == 0) {
		print_help_exit(0);
	}

	if (strncmp("--pid", argv[1], 5) == 0) {
		int pid = atoi(argv[2]);
		if (pid == 0 || pid < 0) {
			pr_err("invalid PID passed");
			return -1;
		}

		tracee->pid = pid;
		return tracee_setup_pid(tracee, pid);
	}

	if (strncmp("--exec", argv[1], 6) == 0) {
		if (tracee_setup_exec(tracee, &argv[2]) == -1) {
			pr_err("error in tracee_setup_exec");
			return -1;
		}

		// let the child exec and wait for it
		if (ptrace(PTRACE_CONT, tracee->pid, NULL, NULL) == -1) {
			pr_err("ptrace conntinue for child failed");
			goto err;
		}

		int wstatus = 0;
		if (waitpid(tracee->pid, &wstatus, 0) < 0) {
			pr_err("waitpid err: %s", strerror(errno));
			goto err;
		}

		if (wstatus >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
			pr_debug("child execed");
			// fetch the memory map base
			if (elf_mem_va_base(tracee) < 0) {
				pr_err("could not get tracee memory VA base "
				       "address, trace failed");
				goto err;
			}
		}

		tracee->state = TRACEE_INIT;
		return 0;
	err:
		kill(tracee->pid, SIGKILL);
		return -1;
	}

	pr_err("invalid usage");
	print_help_exit(1);
}

// TODO: Add signal handler to send SIGINT to tracee instead of debugger

int main(int argc, char *argv[])
{
	if (setup(argc, argv, &global_tracee) == -1) {
		pr_err("error in setting up the tracee");
		return 1;
	}

	sherlock_pid = getpid();

	if (signal(SIGINT, signal_handler) == SIG_ERR) {
		pr_err("error in signal(SIGINT): %s", strerror(errno));
		return 1;
	}

	if (signal(SIGTERM, signal_handler) == SIG_ERR) {
		pr_err("error in signal(SIGTERM): %s", strerror(errno));
		return 1;
	}

	// TODO: Fix pgid and tty ownership
	// if (setpgid(0, 0) == -1) {
	// 	pr_err("error in parent setpgid: %s", strerror(errno));
	// 	return 1;
	// }

#if DEBUG
	assert(global_tracee.state == TRACEE_INIT ||
	    global_tracee.state == TRACEE_STOPPED);
#endif

	char input[SHERLOCK_MAX_STRLEN];
	tracee_state_t ret;

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
		ret = action_parse_input(&global_tracee, input);
		if (ret == TRACEE_ERR) {
			pr_err("critical error, killing debugger");
			return 1;
		}

		if (ret == TRACEE_KILLED) {
			pr_info("the tracee has been killed, exiting debugger");
			return 0;
		}

#if DEBUG
		assert(global_tracee.state == TRACEE_RUNNING ||
		    global_tracee.state == TRACEE_STOPPED);
#endif

		if (global_tracee.state == TRACEE_RUNNING) {
			if (waitpid(global_tracee.pid, &wstatus, 0) < 0) {
				pr_err("waitpid err: %s", strerror(errno));
				return 1;
			}

			if (WIFSTOPPED(wstatus)) {
				pr_info("tracee received signal: %s",
				    strsignal(WSTOPSIG(wstatus)));
			}

			global_tracee.state = TRACEE_STOPPED;
		}
	}

	return 0;
}
