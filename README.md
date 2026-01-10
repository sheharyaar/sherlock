> [!TIP]
> Sherlock (debugger) is ready with basic funtionalities like breakpoint, backtrace, single-step, info, print (inspect), etc. Checkout the sherlock directory for more.

# Sherlock Project

> [!WARNING]
> This project is not to be used in production environments. It is intended for educational purposes only. It is my personal project to learn about system programming, tracing, and debugging on Linux x86_64 systems.

> This project was **not** build using any LLMs. Only the Makefile and some parts of the README.md were generated using LLMs.

The purpose of this project is to create a suite of tracing and debugging tools for Linux x86_64 systems. The tools are inspired by popular existing tools like `strace`, `ltrace`, and `gdb`, but are implemented from scratch to provide a deeper understanding of how these tools work under the hood.

This repository contains source code for the following tracers:
1. `watson`: A system call tracer for Linux x86_64, inspired by `strace`.
2. `irene`: A library call tracer for Linux x86_64, inspired by `ltrace`.
3. `sherlock`: A debugger for Linux x86_64, inspired by `gdb`.

For notes and other information, please open the individual directories, which contain their own `README.md` files.

## Build

The binary will be created in the `build` directory in the root of the project.
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

To run the programs - `./build/<tracer> --help`

> For PID attachment mode you will need `sudo` privileges.

## Sherlock

<figure>
<image src="./image.png" width=500px />
<figcaption> Sherlock in use </figcaption>
</figure>