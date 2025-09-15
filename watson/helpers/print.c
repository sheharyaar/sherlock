/*
 * Watson - System call tracer
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "../syscall_defs.h"

/* using process_vm_readv syscalls to read the data from the remote process.
 PTRACE_PEEKDATA is slower as it only reads a word at a time. process_vm_read
 uses iovec */

void print_write(tracee_t *tracee, unsigned long long args[6])
{
	int fd = args[0];
	unsigned long long remotebuf = args[1];
	size_t count = args[2];

	ssize_t nread;
	char localbuf[34] = { 0 };
	struct iovec local[1];
	struct iovec remote[1];

	size_t toread = MIN(32, count);

	local[0].iov_base = (void *)localbuf;
	local[0].iov_len = 32;
	remote[0].iov_base = (void *)remotebuf;
	remote[0].iov_len = toread;

	nread = process_vm_readv(tracee->pid, local, 1, remote, 1, 0);
	if (nread == -1) {
		pr_err("error in process_vm_readv for signal(%d): %s",
		    tracee->signal, strerror(errno));
		return;
	}

	if (count >= 32) {
		pr_info_raw("%d, \"%s...\", %lu", fd, localbuf, count);
	} else {
		pr_info_raw("%d, \"%s\", %lu", fd, localbuf, count);
	}
}

// void print_execve(tracee_t *tracee, unsigned long long args[6]) {}