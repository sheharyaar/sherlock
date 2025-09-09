/*
   This limit can be found in the kernel source code.
   SYSV Calling convention also mentions the six registers: rdi, rsi, rdx, r10, r8, r9
 */
#define SYSCALL_ARGS_MAX 6

/* 
   Took inspiration from `struct syscall_metadata` in the linux kerneel source file 
   `include/trace/syscall.h`
 */
struct SYSCALL {
	const char *name;
	int syscall_nr;
	int nr_args;
	int types[SYSCALL_ARGS_MAX];
	unsigned long long args[SYSCALL_ARGS_MAX];
} syscall_t;