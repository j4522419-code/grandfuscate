# Architecture

```
source.luau
  -> official luau-ast JSON
  -> AST tagging / declaration map
  -> VM compiler (custom IR, shuffled opcodes, control-flow notes)
  -> encoded constant pool + lazy chunk plans
  -> structural layout and field-key randomization
  -> sharded VM stream fragments + randomized checksums
  -> ticketed group matrices + distributed VM interpreter
  -> token-level field/alias rewrite
  -> opaque ID-numbered return entry
  -> required top Luau banner + one-line comment-free `return` body
```

## Modules

- `obf/ast.py` — official `luau-ast` / `luau-compile` subprocess wrappers.
- `obf/render.py`, `obf/transform.py`, `obf/flatten.py` — source-mode hooks and
  AST rewrite machinery. Normal presets use the VM, not source-mode output.
- `obf/vm/compiler.py` — AST to custom IR; randomized opcodes, operand
  permutations, node order, control-flow transforms, private spans and explicit
  `Unsupported`. Type-only declarations become recorded runtime no-ops.
- `obf/vm/fragments.py`, `obf/vm/nodes.py` — lazy encoded stream fragments and
  three node/operand reconstruction styles (`sparse`, `nested`, `cursor`).
- `obf/vm/runtime.py` — group-scattered interpreter with per-build ticketed
  `eval`/`exec` matrices and guarded handler tables. No central router and no
  central `if op == ...` chain.
- `obf/pool.py`, `obf/runtime.py`, `obf/chunks.py`, `obf/checksum.py` — typed
  constant pool, per-slice lazy chunk plans, reverse-byte constant decode,
  randomized rolling checksums and distributed byte decoders.
- `obf/layout.py`, `obf/names.py`, `obf/fields.py` — per-build VM profiles,
  bank/group matrices, capability tickets, node/dispatch/chunk choices,
  randomized slot bases, confusable names, numeric field keys and token-level
  rewriting.
- `obf/format.py` — five opaque ID-numbered entry layouts, four opaque boot
  layouts, alias-table rewrite and local renaming. No stable semantic names are
  exposed in public metadata.
- `obf/pipeline.py` — orchestration, public keys/stats, private source map and
  syntax validation.
- `obf/cli.py`, `obf/web.py` — CLI and stdlib web service.
- `obf/publish.py` — optional GitHub raw publisher for the loadstring button.

## Generated runtime

Every pool slice and VM stream fragment has its own literal chunk table,
checksum, byte decoder, metadata/cache and dispatch slot. Encoded blobs are
assembled on first use. Constants are decoded byte-by-byte in a rotated reverse
order, then restored with `..`; no single startup `table.concat` or `string.char`
dump contains contiguous source text. Handler tables use randomized 32-bit
opcodes or randomized slot bases, and frame/record fields are opaque numeric
keys.

The private source map contains source spans, opcodes, constants, operand
layout, runtime layout, field keys, chunk plans, control-flow notes and compile
notes. It is never serialized into the production chunk. Public keys contain a
SHA-256 of the private map, not the map itself, and do not contain the detailed
layout/operand/control-flow objects.

## Legacy modules

`obf/vm/armor.py`, `obf/hardening.py` and the nested/anti-environment options
are legacy explicit-experiment code. Normal builds never enable them: the old
environment poisoning could make ordinary executors fail, and the old fixed FNV
pair is a static signature. `obf/hardening.py` is not a security boundary.

## Verification model

Behaviour is checked with official Luau 0.747 (`tools/luau`) and compile-only
`luau-compile --only-parse`. Compatibility fixtures cover executor-like `_G`,
coroutines, metatables, closures, varargs, errors, type-only declarations and
mocked Roblox globals. The production scanner is token-aware: escaped encoded
bytes can contain `--` or short quoted strings without being real comments or
stable fields. The runtime-analysis probe records what a restricted instrumented
environment can recover; it is not a claim about every executor.
