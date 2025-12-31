## Sherlock

A simple debugger using `ptrace` and other required techniques to debug Linux programs. Some features may not be implemented as this is only a learning project.

> This is work in progress. Stay tuned for updates.

### TODOs

- Implement a parser/grammar API for getting the actions, entities, and intents from the text input.
  - [X] Used strtok for basic parsing.
- Implement breakpoint support using INT.
  - [X] Basic breakpoint setting and listing -- works once per breakpoint command (like temporary breakpoints).
  - [ ] Ability to encapsulate/hide the internal breakpoint handling from the user (when the user prints the address of the breakpoint, it should show the original instruction, not the INT instruction).
  - [X] Support temporary and permanent breakpoints.
- Implement debugger symbol support for variables and functions.
  - [ ] Support for functions (DSO and non-DSO).
  - [ ] Support for local variables (watchpoint debugging).
  - [ ] Support for function arguments printing.
- Implement stack unwinding / backtrace support.
  - [X] Look into eh_frame and debug_frame sections for DWARF info.
  - [ ] Implement own backtracer using `eh_frame`

Additional nice to haves:
- [ ] hex, binary and string printing
- [ ] relative addressing modes (with file base, instruction pointer) when using commands like print
- [ ] source level debugging
- [ ] Disassembled view

### Notes

<TODO>

### Pending Features (Not to be implemented)

<TODO>

### Build and Run

<TODO>

### Resources

<TODO>
