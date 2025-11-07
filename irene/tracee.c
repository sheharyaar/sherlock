/*
 * Irene - Library call tracer
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#define _GNU_SOURCE
#include "log.h"
#include "tracee.h"
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

// Prints the help message and exits with status 'ret'
static void __attribute((noreturn)) exit_help(int ret)
{
	pr_info_raw("usage:\n");
	pr_info_raw("./irene --exec program arg1 arg2 ...\n");
	exit(ret);
}

// Attaches ptrace tracer with 'options'. Returns -1 on error.
static int attach_and_start(tracee_t *tracee, int options)
{
	// attach to the program
	if (ptrace(PT_ATTACH, tracee->pid, NULL, 0) == -1) {
		pr_err("ptrace failed: %s", strerror(errno));
		return -1;
	}
	pr_debug("ptrace attach");

	// need the tracee to stop to set options
	if (waitpid(tracee->pid, NULL, 0) == -1) {
		pr_err("waitpid err: %s", strerror(errno));
		goto err;
	}
	pr_debug("waitpid attach");

	if (options != 0) {
		if (ptrace(PTRACE_SETOPTIONS, tracee->pid, NULL, options) ==
		    -1) {
			pr_err("ptrace setopts failed: %s", strerror(errno));
			goto err;
		}
		pr_debug("ptrace setoptions");
	}

	// start tracing the tracee at syscalls
	if (ptrace(PTRACE_SYSCALL, tracee->pid, NULL, 0) < 0) {
		pr_err("getregs error: %s", strerror(errno));
		goto err;
	}
	pr_debug("ptrace syscall");

	return 0;
err:
	ptrace(PTRACE_DETACH, tracee->pid, NULL, NULL);
	return -1;
}

// The setup routine, initialises the tracee var and fork-execs if required
int tracee_setup(int argc, char *argv[], tracee_t *tracee)
{
	if (argc < 3)
		exit_help(1); // noreturn

	if (strncmp(argv[1], "--help", strlen("--help")) == 0)
		exit_help(0); // noreturn

	if (strncmp(argv[1], "--exec", strlen("--exec")) == 0) {
		// setup pipe for communication
		int pipefd[2];
		int flag;
		int ret;

		if (pipe(pipefd) == -1) {
			pr_err("error in pipefd: %s", strerror(errno));
			exit(1);
		}

		if ((ret = fork()) == -1) {
			pr_err("fork failed: %s", strerror(errno));
			exit(1);
		}

		// handle child
		if (ret == 0) {
			close(pipefd[1]);

			// wait for parent to setup the tracer, etc.
			if (read(pipefd[0], &flag, sizeof(int)) == -1) {
				pr_err(
				    "error in child read: %s", strerror(errno));
				_exit(1);
			}

			// now exec into the program
			if (execvp(argv[2], &argv[2]) == -1) {
				pr_err(
				    "error in child exec: %s", strerror(errno));
				_exit(1);
			}
		}

		tracee->pid = ret;
		strncpy(tracee->file_name, argv[2], 256);
		tracee->file_name[255] = '\0';

		close(pipefd[0]);

		if (attach_and_start(
			tracee, PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC) == -1) {
			pr_err("attach failed for exec child");
			goto parent_err;
		}

		// signal the child to exec
		if (write(pipefd[1], &flag, sizeof(int)) == -1) {
			pr_err("error in parent write: %s", strerror(errno));
			goto parent_err;
		}

		return 0;

	parent_err:
		kill(tracee->pid, SIGKILL);
		exit(1);
	}

	return -1;
}