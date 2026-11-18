# Runtime-analysis probe, third pass

Measured 2026-11-18T06:15:00.099574+00:00 with official Luau 0.747, seed 20261118, exact fixture `print("Hello World!")`.

Runtime observation of `Hello World!` is expected; the program must execute. This probe checks that one obvious decoder function, one captured instruction table, or one global dispatcher does not expose the whole payload, and that simple dumps do not reconstruct a clean IR.

| Level | Preset | Bytes | Capture | Startup dump | All simple dump | Whole payload tables | Whole payload functions | Clean IR | Result |
|---|---|---:|---|---:|---:|---:|---:|---|---|
| light | light | 154,402 | `Hello World!` | 0 | 0 | 0 | 0 | false | PASS |
| balanced | medium | 198,810 | `Hello World!` | 0 | 0 | 0 | 0 | false | PASS |
| aggressive | heavy | 607,349 | `Hello World!` | 0 | 0 | 0 | 0 | false | PASS |

## Probes and limitations

- One obvious decoder: captured functions were called with index values only; no single function returned all needles.
- One instruction table: captured tables and nested tables were probed; no single table returned all needles, and no obvious small-keyed instruction handler table was identified.
- One dispatcher: no central numeric dispatch chain or recognizably named global dispatcher was found; portable `debug.sethook` is not available in this toolchain.
- Simple startup/all dumps, `string.char` streams and IR-marker reconstruction did not recover the source needles. The instrumented `table.pack` wrapper did see the final 13-byte print argument; this is runtime library-call observation, not a central decoder dump.
- A capable executor-specific debugger can still inspect locals, upvalues, standard library hooks and `print`; client-side scripts remain recoverable.

Scanner findings: 0. Third-pass checks: 67. Failures: 0.
