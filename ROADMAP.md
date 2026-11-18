# Roadmap

## Completed

- [x] Official Luau 0.747 parsing, compile checks and behaviour tests.
- [x] One polymorphic VM runtime with shuffled 32-bit opcodes and encoded IR.
- [x] Light, medium and heavy presets with safe one-line output.
- [x] Return at byte 0, zero comments, zero top-level locals, no dynamic loader.
- [x] Lazy/chunked constant-pool and VM-stream payload storage.
- [x] Per-build structural layout, randomized slot bases and numeric field keys.
- [x] Removal of stable router, field, checksum, format and library wording
      signatures from production output.
- [x] Explicit `vm.Unsupported`; type-only declarations recorded as no-ops.
- [x] `print(67)` and complex fixture differential verification, including
      top-level return values.
- [x] Restricted-runtime analysis probe, five-build diversity, old-vs-improved
      benchmark, scanner/private-map/full-suite verification.
- [x] Third-pass ticketed group matrices with no central decoder/dispatcher,
      per-build VM structure, spread source constants and exact Hello World
      production/runtime-analysis evidence.
- [x] Refreshed examples, reports, benchmark sanity ceilings and documentation.

## Not claimed / not done

- [ ] No 100% decompile-proof client-side protection.
- [ ] No proof of superiority over Luraph, LuaProtect or any commercial product.
- [ ] No red-team benchmark against real deobfuscators or executor-specific
      debuggers.
- [ ] No live Roblox executor certification; official Luau and mocked fixtures
      are the current compatibility evidence.
- [ ] No real security boundary for client scripts; server-side authority is
      still required.

## Deployment

Deployment is paused by user instruction. The repo is local-only: no Git
remote, no push, no GitHub repository and no Render service. `render.yaml`,
`Dockerfile` and `DEPLOY.md` are prepared for a future decision, not active
hosting.

## Possible future work

- Optional red-team evaluation with permission and a controlled harness.
- More Luau grammar coverage driven by `Unsupported` reports rather than silent
  fallback.
- Performance profiling of the tree-walker hot path.
- Additional executor compatibility fixtures contributed by users.
