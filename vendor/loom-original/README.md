# Loom Original (core) — vendored source

Vendored verbatim from the Loom source distribution supplied by the project
author (`loom-original-core.zip`, SHA-256 `6a1148452166b484a9e1a05b3e364358c38ce300a7ac8bb19755123bc35c371b`).
Not modified.

- `loom.py` — AST -> register bytecode compiler and single-file emitter.
  Requires `luau-ast` on PATH (or `LUAU_AST` pointing at it).
- `runtime.luau.in` — VM runtime template (`@FUNCTIONS@` / `@DISPATCH@`).

The Original edition supports a deliberately small Luau subset (globals
`workspace`, `game`, `print`, `type`, `tostring`, `tonumber`, `assert`,
`select`; no `string.*`/`table.*`/`ipairs`/`pairs`). Scripts outside the
subset are rejected with an explicit `Unsupported` error naming the node;
there is no silent downgrade. The `loom-2.4` edition in the full Loom
distribution covers complete Luau via the official bytecode compiler and the
MIT-licensed Fiu interpreter modifications.

Licenses for third-party components (Fiu, Luau, CPython, Go, VC++ runtime)
are only relevant to the other editions/vendor bundle and are intentionally
not stripped or altered anywhere in this repository.
