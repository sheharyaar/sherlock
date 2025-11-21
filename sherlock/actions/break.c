/*
 * Sherlock - A Minimal Debugger
 * Part of the Sherlock project
 *
 * Copyright (c) 2025 Mohammad Shehar Yaar Tausif
 *
 * This file is licensed under the MIT License.
 */

#include "../action.h"

/*
TODO:
- Function name
- Address
- File:line
- Conditional ?

* List of breakpoints
* Ability to add / remove breakpoints
* Use INT to add breakpoint -- maybe first implement it in ltrace, compare
performance and then port to debugger.
*/

REG_ACTION(break) { RET_ACTION(tracee, TRACEE_STOPPED); }