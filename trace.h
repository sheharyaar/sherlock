#ifndef _TRACE_H
#define _TRACE_H

#include <unistd.h>

typedef enum state { UNATTACHED, ENTRY, EXIT } state_t;

typedef struct TRACEE {
	pid_t pid;
	state_t state;
} tracee_t;

#define tracee_continue_syscall()                                              \
	do {                                                                   \
		if (ptrace(PTRACE_SYSCALL, tracee.pid, NULL, 0) == -1) {       \
			pr_err("ptrace cont err: %s", strerror(errno));        \
			goto err;                                              \
		}                                                              \
	} while (0)

#endif