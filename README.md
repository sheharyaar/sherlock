# Sherlock Project

The purpose of this project is to create a suite of tracing and debugging tools for Linux x86_64 systems. The tools are inspired by popular existing tools like `strace`, `ltrace`, and `gdb`, but are implemented from scratch to provide a deeper understanding of how these tools work under the hood.

> These projects will accompany a series of blog posts that will explain the implementation details and the concepts involved in building them. I will also try to do a kernel study to understand how the Linux kernel supports these functionalities.

This repository contains source code for the following tracers:
1. `watson`: A system call tracer for Linux x86_64, inspired by `strace`.
2. `irene`: A library call tracer for Linux x86_64, inspired by `ltrace`.
3. `sherlock`: A debugger for Linux x86_64, inspired by `gdb`.

> Note: At this point only `watson` is fully functional. `irene` and `sherlock` are still under development.

## Build

You can either build the tracers individually or all at once. For building all at once, run:
```bash
make all
```

To build individual tracers, use:
```bash
make watson
make irene
make sherlock
```

Or you can also open the individual directories and run `make` there.