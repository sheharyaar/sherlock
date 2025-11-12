/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "log.h"
#define _GNU_SOURCE
#include "sherlock.h"
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
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
	.breakpoints = NULL,
	.va_base = 0,
	.name[0] = '\0',
};

void __attribute__((noreturn)) print_help_exit(int status)
{
	pr_info_raw("Usage:\n");
	pr_info_raw("$ sudo sherlock --pid PID\n");
	pr_info_raw("$ sherlock --exec program [args]\n");
	pr_info_raw("In cases where both --pid and --exec are present, --pid "
		    "will be used\n");
	exit(status);
}

// Sets up tracee and brings it to a stopped state.
// TODO: exec tracee notes.
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

		return 0;
	err:
		kill(tracee->pid, SIGKILL);
		return -1;
	}

	pr_err("invalid usage");
	print_help_exit(1);
}

int main(int argc, char *argv[])
{
	if (setup(argc, argv, &global_tracee) == -1) {
		pr_err("error in setting up the tracee");
		return 1;
	}

	bool terminate = false;

	// at this point the tracee is spawned (if --exec), ptrace
	// attached and stopped.
	char input[SHERLOCK_MAX_STRLEN];
	while (!terminate) {
		dbg_prompt(input, SHERLOCK_MAX_STRLEN);
		input_parse(input);
	}

	return 0;
}
