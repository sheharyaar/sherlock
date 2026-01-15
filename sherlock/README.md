## Sherlock

A simple debugger using `ptrace` and other required techniques to debug Linux programs. Some features may not be implemented as this is only a learning project.

> Milestone v0.1: basic funnctionalities done.

### Notes

This project brought a lot of insights into how debuggers like GDB work under the hood. I became aware of some techniques used by debuggers to boost performance, like setting breakpoints by replacing instructions with INT instructions, using `r_debug (DT_DEBUG)` for getting notified when new libraries are loaded, using `/proc/<pid>/mem` for reading/writing memory, etc.

> I have written a series of blog on some of the core concepts used in building the debugger. You can find it on my blog site: [Writing a Debugger form Scratch](https://www.sheharyaar.in/blog/writing-a-debugger-00)

### Pending Features (Not to be implemented / Nice to haves)

Not to be implemented:
- OS other than Linux.
- Architectures other than x86_64.

Nice to haves:
- [ ] Implement own backtracer using `eh_frame`
- [ ] Ability to encapsulate/hide the internal breakpoint handling from the user (when the user prints the address of the breakpoint, it should show the original instruction, not the INT instruction).
- [ ] hex, binary and string printing
- [ ] relative addressing modes (with file base, instruction pointer) when using commands like print
- [ ] source level debugging
- [ ] Disassembled view

### Build and Run

- Normal mode: `make`
- Debug mode: `make DEBUG=1`

The binary will be created under the `build/` directory in the project root.
- Usage from curent directory: `../build/sherlock --exec <program> [args...]`
- For already running process: `sudo ../build/sherlock --pid <pid>`

### Resources

- [Notes on Hardware Breakpoints and Watchpoints](https://aarzilli.github.io/debugger-bibliography/hwbreak.html)
- [GDB Wiki: Breakpoint Handling](https://sourceware.org/gdb/wiki/Internals/Breakpoint%20Handling)
- [GDB Wiki: How GDB loads symbol files](https://sourceware.org/gdb/wiki/How%20gdb%20loads%20symbol%20files)
- [An Introduction to Stack Unwinding and Exception Handling](https://www.zyma.me/post/stack-unwind-intro/)
- [All about Global Offset Table](https://maskray.me/blog/2021-08-29-all-about-global-offset-table)
- [Exception frames - Linux Refspec](https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html)
- [How the GDB debugger and other tools use call frame information to determine the active function calls](https://opensource.com/article/23/3/gdb-debugger-call-frame-active-function-calls?extIdCarryOver=true&sc_cid=RHCTG0180000382541)
- [Frame pointers: Untangling the unwinding](https://developers.redhat.com/articles/2023/07/31/frame-pointers-untangling-unwinding#)
- [Understanding `_dl_runtime_resolve()`](https://ypl.coffee/dl-resolve/)
