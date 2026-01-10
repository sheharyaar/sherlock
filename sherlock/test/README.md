<!-- written with help of CHATGPT -->

## Breakpoint Test matrix

-   plt -> `R_X86_64_JUMP_SLOT`
-   no-PLT -> `R_X86_64_GLOB_DAT`
-   CET / IBT enabled -> `plt.sec`
-   pie -> randomizes address base

| Binary                   | PIE | PLT | CET | Expected relocation                                                                               | GDB Status | Sherlock Status |
| ------------------------ | --- | --- | --- | ------------------------------------------------------------------------------------------------- | ---------- | --------------- |
| `t-nopie-plt-nocet`      | ❌  | ✅  | ❌  | `R_X86_64_JUMP_SLOT`, `.plt`                                                                      | ✅         | ✅              |
| `t-nopie-plt-cet`        | ❌  | ✅  | ✅  | `R_X86_64_JUMP_SLOT`, `.plt.sec`                                                                  | ✅         | ✅              |
| `t-nopie-noplt`          | ❌  | ❌  | —   | `R_X86_64_GLOB_DAT`                                                                               | ✅         | ✅              |
| `t-pie-plt-nocet`        | ✅  | ✅  | ❌  | `R_X86_64_JUMP_SLOT`, `.plt` (PIE semantics)                                                      | ✅         | ✅              |
| `t-pie-plt-cet`          | ✅  | ✅  | ✅  | `R_X86_64_JUMP_SLOT`, `.plt.sec` (PIE semantics)                                                  | ✅         | ✅              |
| `t-pie-noplt`            | ✅  | ❌  | —   | `R_X86_64_GLOB_DAT` (PIE semantics)                                                               | ✅         | ✅              |
| `t-static`               | ❌  | ❌  | ❌  | no dynamic symbols, all _static_                                                               | ✅         | ✅              |
| `t-stripped-pie-plt-cet` | ❌  | ❌  | ❌  | should work as `t-pie-plt-cet` for dynamic symbols; <br> should not break static symbols like `<main>` | ✅         | ✅              |
| `t-stripped-static`      | ❌  | ❌  | ❌  | should not break any symbol, daynamic (`puts`) as well as static(`<main>`)                        | ✅         | ✅              |
