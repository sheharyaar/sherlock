## Irene

A simple library call tracer written in C using `ptrace`. It can trace library calls made by a program.

### Notes

This program helped me understand how `ptrace` can be used to single-step a process and read the `.text` section of a process. It also required me to understand the different sections, dynamic linking process and the mapping of ELF sections to memory. 

### Pending Features (Not to be implemented)

Some features are still pending implementation, which won't be implemented in the near future as this is just a learning project. These include:
- OS other than Linux
- Architectures other than x86_64
- Printing arguments with their correct types (only the hex values for first four arguments are printed).
- Return value of the function calls

To implement argument value printing, we would need to have a database of function signatures, which is out of scope for this project. After getting the database, we would need to parse the signature and then copy the data from the traced process's memory to our process's memory using `ptrace(PTRACE_PEEKDATA)` or `process_vm_readv`.

### Build and Run

Irene can be built both from the root directory of the project or from the current directory.
- Normal mode: `make`
- Debug mode: `make DEBUG=1`

The binary will be created in the `build` directory in the root of the project.
- Usage from current directory: `../build/irene --exec <program> [args...]`
- Usage from root directory: `./build/irene --exec <program> [args...]`

### Resources

- [ptrace man page](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [x86_64 ABI](https://www.uclibc.org/docs/psABI-x86_64.pdf)
- [ELF Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [ELF man page](https://man7.org/linux/man-pages/man5/elf.5.html)
- [libelf by Example - Joseph Koshy](https://atakua.org/old-wp/wp-content/uploads/2015/03/libelf-by-example-20100112.pdf)
