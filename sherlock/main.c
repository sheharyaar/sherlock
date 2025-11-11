/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#define _GNU_SOURCE
#include "sherlock.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static tracee_t global_tracee = { 0, NULL, '\0' };

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
		return tracee_setup_exec(tracee, &argv[2]);
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

	return 0;
}
