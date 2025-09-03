#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/user.h>
#include "strsyscall.h"

#define pr_err(fmt, ...) printf("[ERR] " fmt "\n", ##__VA_ARGS__)
#define pr_info(fmt, ...) printf("[INF] " fmt "\n", ##__VA_ARGS__)
#define pr_warn(fmt, ...) printf("[WRN] " fmt "\n", ##__VA_ARGS__)

pid_t target_pid = -1;
bool terminate = 0;

/* Source: System V ABI for AMD64 structure, section A.2.1 (Calling Conventions)*/
void print_user_registers(struct user_regs_struct *reg)
{
	/* To differentiate between syscall-entry-stop and syscall-exit-stop 
		and also between other SIGTRAPs,there are a couple of methods:
		
		1. PTRACE_GETSIGINFO can help to get the details of the signal that stopped
			the tracees. Checkout man page for coditions involving `si_info` that
			helps determine the cause of SIGTRAP.
		
		2. If the value of rax is equal to -ENOSYS that is ...ffffffffda, then
			it's an entry, SIGTRAP (in the tracee's case) happens _after_ the
			syscall-exit-stop, so any other value can be considered to be part of
			syscall-exit-stop, but "such detection is fragile and is best avoided."

		3. Using the PTRACE_O_TRACESYSGOOD option is the recommended method to 
			distinguish syscall-stops from other kinds of ptrace-stops since it 
			is reliable and does not incur a performance penalty.

		Note: Syscall-enter-stop and syscall-exit-stop are indistinguishable
			from each other by the tracer.  The tracer needs to keep track of
			the sequence of ptrace-stops in order to not misinterpret syscall-
			enter-stop as syscall-exit-stop or vice versa.  In general, a
			syscall-enter-stop is always followed by syscall-exit-stop,
			PTRACE_EVENT stop, or the tracee's death; no other kinds of
			ptrace-stop can occur in between.  However, note that seccomp
			stops (see below) can cause syscall-exit-stops, without preceding
			syscall-entry-stops.  If seccomp is in use, care needs to be taken
			not to misinterpret such stops as syscall-entry-stops.

		Source: https://man7.org/linux/man-pages/man2/ptrace.2.html 
	*/
	pr_info("rax: %016llx", reg->rax);
	pr_info("orig_rax: %016llx", reg->orig_rax);
	pr_info("orig syscall: %s", str_syscall(reg->orig_rax));
	pr_info("syscall: %s", str_syscall(reg->rax));
	pr_info("-----------------");
	// pr_info("rdi: %016llx", reg->rdi);
	// pr_info("rsi: %016llx", reg->rsi);
	// pr_info("rdx: %016llx", reg->rdx);
	// pr_info("r10: %016llx", reg->r10);
	// pr_info("r08: %016llx", reg->r8);
	// pr_info("r09: %016llx", reg->r9);
}

void exit_handler(void)
{
	pr_info("detaching the debugger and exiting");

	// detach the tracer
	if (target_pid != -1) {
		int ret = ptrace(PT_DETACH, target_pid, NULL, 0);
		if (ret < 0) {
			pr_err("ptrace detach failed: %s", strerror(errno));
		}
	}
}

void signal_handler(int)
{
	terminate = 1;
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		pr_err("invalid number of arguments received (%d)", argc);
		return 1;
	}

	if (atexit(exit_handler) < 0) {
		pr_err("error in atexit: %s", strerror(errno));
		return 1;
	}

	// setup exit handler on SIGTERM
	if (signal(SIGINT, signal_handler) == SIG_ERR) {
		pr_err("signal call failed %s: ", strerror(errno));
		return 1;
	}

	if (signal(SIGTERM, signal_handler) == SIG_ERR) {
		pr_err("signal call failed %s: ", strerror(errno));
		return 1;
	}

	target_pid = atoi(argv[1]);
	pr_info("tracing PID: %d", target_pid);

	// attach to the program
	int ret = ptrace(PT_ATTACH, target_pid, NULL, 0);
	if (ret < 0) {
		pr_err("ptrace failed: %s", strerror(errno));
		return 1;
	}

	while (!terminate) {
		int wstatus;
		if (waitpid(target_pid, &wstatus, 0) < 0) {
			pr_err("waitpid err: %s", strerror(errno));
			return 1;
		}

		// print the stop information
		if (WIFSTOPPED(wstatus)) {
			pr_info("tracee stopped by signal: %s",
				strsignal(WSTOPSIG(wstatus)));
		}

		// print_regsters
		struct user_regs_struct regs;
		if (ptrace(PTRACE_GETREGS, target_pid, NULL, &regs) < 0) {
			pr_err("peekuser error: %s", strerror(errno));
			return 1;
		}

		print_user_registers(&regs);

		if (WIFCONTINUED(wstatus)) {
			pr_info("tracee was CONTinued");
		}

		// stop at next systemcall
		if (ptrace(PTRACE_SYSCALL, target_pid, NULL, 0) < 0) {
			pr_err("getregs error: %s", strerror(errno));
			return 1;
		}
	}

	return 0;
}
