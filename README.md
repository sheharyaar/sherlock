## Sherlock

A simple syscall tracer written in C using `ptrace`. It can trace system calls made by a program and print their names along with arguments and return values.

### Build and Run

1. Build using: `make`. If you want to build in debug mode, use `make DEBUG=1`.
2. Run the tracer with a target pid: `sudo ./sherlock <pid>`.

### TODO

- [X] Ptrace a PID
	- [X] Inspect registers or syscalls
	- [ ] Print the syscalls arguments and return values in a human-readable format
	- [ ] Inspect if sudo is always needed for running trace
- [X] Ptrace a child PID (running a command and tracing it)
- [X] Test various options of PID

After the syscall tracer, I will work on add a debugger to Sherlock

### Resources

- [ptrace man page](https://man7.org/linux/man-pages/man2/ptrace.2.html)
