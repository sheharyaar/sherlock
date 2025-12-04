/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "sherlock.h"
#include <asm-generic/errno-base.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#define PROC_CMDLINE "/proc/%d/cmdline"

// Reads the /proc/<PID>/cmdline file and sets the tracee executable name.
// Returns -1 on error.
static int get_pid_cmdline(tracee_t *tracee, int pid)
{
	// get the name of the file
	char name[SHERLOCK_MAX_STRLEN];
	char cmdline_file[SHERLOCK_MAX_STRLEN];
	FILE *cmdline_f = NULL;

	if (snprintf(cmdline_file, SHERLOCK_MAX_STRLEN, PROC_CMDLINE, pid) <
	    0) {
		pr_err("snprint failed: %s", strerror(errno));
		return -1;
	}

	if ((cmdline_f = fopen(cmdline_file, "r")) == NULL) {
		pr_err("opening pid map file failed: %s", strerror(errno));
		return -1;
	}

	if (fscanf(cmdline_f, "%s ", name) == EOF) {
		pr_err("error in fscanf: %s", strerror(ferror(cmdline_f)));
		if (errno == ENOMEM) {
			pr_warn("a possible reason can be that the "
				"/proc/%d/cmdline is more than %d bytes",
			    pid, SHERLOCK_MAX_STRLEN);
		}
		fclose(cmdline_f);
		return -1;
	}

	strncpy(tracee->name, name, SHERLOCK_MAX_STRLEN);
	tracee->name[SHERLOCK_MAX_STRLEN - 1] = '\0';

	fclose(cmdline_f);
	return 0;
}

// Attaches ptrace tracer with 'options' and stops the tracee.
// Returns -1 on error.
static int attach_and_stop(tracee_t *tracee, bool exec_stop)
{
	// attach to the program, this sends a SIGSTOP to the tracee. Collect
	// the status using waitpid().
	if (ptrace(PTRACE_ATTACH, tracee->pid, NULL, 0) == -1) {
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

	// This is only executed if the debugger is launched with --exec
	if (exec_stop) {
		if (ptrace(PTRACE_SETOPTIONS, tracee->pid, NULL,
			PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC) == -1) {
			pr_err("ptrace setopts failed: %s", strerror(errno));
			goto err;
		}
		pr_debug("ptrace setoptions");
	}

	return 0;
err:
	ptrace(PTRACE_DETACH, tracee->pid, NULL, NULL);
	return -1;
}

// Attaches the debugger to the process with PID and sets the fields of the
// tracee. The tracee will be in stopped state, you can perform other oeprations
// and then you need to 'continue' the process.
// Returns -1 on error.
int tracee_setup_pid(tracee_t *tracee, int pid)
{
	// get the cmdline name of the process
	if (get_pid_cmdline(tracee, pid) == -1) {
		pr_err("error in get_pid_cmdline");
		return -1;
	}
	pr_debug("pid cmdline: %s", tracee->name);

	// attach to the program, the tracee should be left in the stopped
	// state, since the program is already running, unlike the exec case
	if (attach_and_stop(tracee, false) == -1) {
		pr_err("attach_and_start failed");
		return -1;
	}

	return 0;
}

// Execs the program andd attaches the deubgger to it. Sets the fields of the
// tracee. Returns -1 on error.
int tracee_setup_exec(tracee_t *tracee, char *argv[])
{
	if (strlen(argv[0]) >= SHERLOCK_MAX_STRLEN) {
		pr_err("the exec program path is too long");
		return -1;
	}

	// exec the program, perform IPC for communicating when to exec
	// and fetching the
	int pipefd[2];
	int flag;
	pid_t cpid;

	if (pipe(pipefd) == -1) {
		pr_err("pipe failed: %s", strerror(errno));
		return -1;
	}

	cpid = fork();
	if (cpid == -1) {
		pr_err("fork failed: %s", strerror(errno));
		return -1;
	}

	// child's block of code
	if (cpid == 0) {
		// close the write end of pipe
		close(pipefd[1]);

		// wait for parent to setup the tracer, etc.
		if (read(pipefd[0], &flag, sizeof(int)) == -1) {
			pr_err("error in child read: %s", strerror(errno));
			_exit(1);
		}

		// TODO: Fix pgid and tty ownership
		// if (setpgid(0, 0) == -1) {
		// 	pr_err("error in child setpgid: %s", strerror(errno));
		// 	_exit(1);
		// }

		// now exec into the program
		if (execvp(argv[0], &argv[0]) == -1) {
			pr_err("error in child exec: %s", strerror(errno));
			_exit(1);
		}
	}

	tracee->pid = cpid;
	strncpy(tracee->name, argv[0], SHERLOCK_MAX_STRLEN);
	tracee->name[SHERLOCK_MAX_STRLEN - 1] = '\0';

	// close read end of the pipe for parent
	close(pipefd[0]);

	if (attach_and_stop(tracee, true) == -1) {
		pr_err("attach_and_stop failed");
		goto parent_err;
	}

	// signal the child to exec
	if (write(pipefd[1], &flag, sizeof(int)) == -1) {
		pr_err("error in parent write: %s", strerror(errno));
		goto parent_err;
	}

	return 0;

parent_err:
	kill(cpid, SIGKILL);
	return -1;
}