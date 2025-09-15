## Watson

A simple syscall tracer written in C using `ptrace`. It can trace system calls made by a program and print their names along with arguments and return values.

### Pending Features

1. Only `write` syscall prints its arguments currently. To implement argument printing for other syscalls, perform the following steps:
   - Identify the syscall number and its corresponding argument types from the syscall table.
   - The file `syscall_list.h` contains a macro `SYSCALL_DEFINE` which maps syscall numbers to their names and printing functions. So for the syscall you want to implement, change the third argument from NULL of the macro to a function that prints the arguments.
   ```c
   SYSCALL_DEFINE(5, fstat, print_fstat)
   ```
   - Open `helpers/print.c` and implement the function `print_fstat` to print the arguments of the `fstat` syscall.

> Note: To copy data from the traced process, use `process_vm_readv` instead of `ptrace(PTRACE_PEEKDATA)` for better performance.

2. In the trace for execed process, the first syscall `execve` has the args as `(0, 0, 0)`. This is a bug and needs to be fixed.

### Build and Run

1. Build using: `make`. If you want to build in debug mode, use `make DEBUG=1`.
2. To attach the tracer to existing process: `sudo ./watson --pid <pid>`.
3. To start a new process and trace it: `sudo ./watson --exec <program> [args...]`.


### Resources

- [System V Application Binary Interface AMD64](https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf)
- [ptrace(2) man page](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [process_vm_readv(2) man page](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)
