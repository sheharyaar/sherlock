/*
 * Watson - System call tracer
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#ifndef _SYSCALL_DEFS_H
#define _SYSCALL_DEFS_H

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <string.h>
#include <errno.h>
#include "tracee_defs.h"
#include "log.h"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

// Print handlers for syscalls
#define SYSCALL_DEFINE(SYS_NR, SYS_NAME, SYS_PRINT)                            \
	void print_##SYS_NAME(tracee_t *tracee, unsigned long long args[6]);

#include "syscall_list.h"

#undef SYSCALL_DEFINE

/*
   This limit can be found in the kernel source code.
   SYSV Calling convention also mentions the six registers: rdi, rsi, rdx, r10,
   r8, r9
 */
#define SYSCALL_ARGS_MAX 6

typedef void (*print_handler_t)(
    tracee_t *tracee, unsigned long long args[SYSCALL_ARGS_MAX]);

/*
   Took inspiration from `struct syscall_metadata` in the linux kerneel
   source file `include/trace/syscall.h`
 */
typedef struct SYSCALL {
	const char *name;
	print_handler_t print;
} syscall_t;

#define SYSCALL_DEFINE(SYS_NR, SYS_NAME, SYS_PRINT)                            \
	[SYS_NR] = { .name = #SYS_NAME, .print = SYS_PRINT },

static const syscall_t syscall_list[] = {
#include "syscall_list.h"
};

static inline const syscall_t *get_syscall(unsigned long long i)
{
	return i < (sizeof(syscall_list) / sizeof(syscall_t)) ? &syscall_list[i]
							      : NULL;
}

#endif
