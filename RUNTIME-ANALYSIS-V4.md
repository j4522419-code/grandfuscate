# Runtime-analysis probe, V4 (integrity + decoy traps + entropy)

Measured 2026-11-19T07:53:19.786964+00:00 with official Luau 0.747, seed 20261118, fixture `print("Hello World!")`.

| Preset | Bytes | Manifest | Decoys | Wrong-ticket errors | Valid-ticket defaults | Window clean/tamper | Decoder tamper | Bare globals | Scanner |
|---|---:|---:|---:|---:|---:|---|---|---:|---:|
| light | 147,673 | 10,540 B | 8 | 104 | 8 | OK_TRUE/OK_FALSE | rc=0 | 0 | 0 |
| medium | 209,143 | 23,299 B | 24 | 312 | 24 | OK_TRUE/OK_FALSE | rc=0 | 0 | 0 |
| heavy | 657,027 | 219,745 B | 64 | 832 | 64 | OK_TRUE/OK_FALSE | rc=0 | 0 | 0 |

## Probes and results

- Wrong-ticket decoy calls raise a controlled `error(<opaque const>)` deterministically with `HANG=0`; valid-ticket calls return a harmless default. Decoys are inert and never called by the real VM path.
- A clean 96-byte window verifies (`OK_TRUE`); a one-symbol tamper is detected (`OK_FALSE`). The same marker tampered inside the shipped chunk degrades the real decoder to a harmless default (rc=0, no error, no hang) rather than raising.
- v4-emitted code has no `while`/`repeat`/unbounded loops; window checks are seven bounded `for j = 1, 96` loops; the VM's pre-existing stream-bounded dispatch `while true do` is unchanged and adds no new loop.
- `error`, `bit32.bxor`, `type`, `string.byte` are alias-rewritten: zero bare forbidden globals in shipped chunks. No `loadstring` / `HttpGet` self-decoding wrapper; symbol soup lives only inside string literals.
- Scanner findings: 0. Combined v4 checks: 211, failures: 0.

## Limitations

Obfuscation decoys, not a security boundary. Client scripts remain recoverable to an analyst who executes/debugs them; runtime observation of output strings is unavoidable. No 100% dumper/env-logger defeat claim, no red-team or executor certification. Official Luau debug hooks are nil.
