## Sherlock

A simple debugger using `ptrace` and other required techniques to debug Linux programs. Some features may not be implemented as this is only a learning project.

> This is work in progress. Stay tuned for updates.

### TODOs

- Logically rearrange the code, already broken in actions, entities, now break the waits (stops) into signal stops, breakpoint stops, etc.
  - [ ] Each action should register its handlers with a specific signature (entity, args).
  - [ ] Each stop type (event) should also have a handler to make it easy to handle permanent breakpoints.
- Implement a parser/grammar API for getting the actions, entities, and intents from the text input.
  - [X] Used strtok for basic parsing.
- Implement breakpoint support using INT.
  - [X] Basic breakpoint setting and listing -- works once per breakpoint command (like temporary breakpoints).
  - [ ] Ability to encapsulate/hide the internal breakpoint handling from the user (when the user prints the address of the breakpoint, it should show the original instruction, not the INT instruction).
  - [ ] Support temporary and permanent breakpoints.
- Implement debugger symbol support for variables and functions.
  - [ ] Support for PLT symbols.
  - [ ] Support for local variables.
  - [ ] Support for function arguments.
- Implement stack unwinding / backtrace support.
  - [ ] Look into eh_frame and debug_frame sections for DWARF info.
- Implement watchpoints using hardware breakpoints.

Additional nice to haves:
- [ ] hex, binary and string printing
- [ ] relative addressing modes (with file base, instruction pointer) when using commands like print

### Notes

<TODO>

### Pending Features (Not to be implemented)

<TODO>

### Build and Run

<TODO>

### Resources

<TODO>