# Development Log — Rex C-- (Cmm) Backend

Chronological record of the Cmm backend: what was built, in what order, every
defect encountered, and how each was diagnosed and fixed.

**Scope note on granularity.** Entries are ordered by work phase rather than by
wall-clock minute. I did not keep a timer, and inventing timestamps would be
worse than useless when reconstructing a debugging session. What is recorded
faithfully is the *sequence* of investigations, which is the part that actually
helps when a similar bug reappears.

**Related:** `ReadmeCmm.md` (user manual), `tools/test_cmm_parity.sh`
(differential test).

---

## 1. Executive Summary

### 1.1 Milestone achieved

A working, default-preserving Cmm backend for Rex that compiles programs to
standalone C-- and links them to native executables with **no GHC RTS**.

**Final state: `pass=31 fail=0 known=6` across all 37 examples** in
`rex/examples/`, where every `pass` is a case where the Cmm target produced
output *byte-identical* to the reference C target.

### 1.2 The four substantive technical wins

1. **A working calling convention without the RTS.** Cmm cannot be called from
   C, and Cmm has no type-directed call machinery of its own. The solution is a
   uniform `W_`-pointer value representation plus **243 auto-generated C shim
   functions** so that every runtime operation is a leaf call Cmm can make. A
   64 MiB manually-managed stack and a `setjmp` landing pad complete the
   illusion of a normal language runtime.

2. **Fixing a `strlen` truncation that silently corrupted every multi-field
   struct.** Struct field names are a NUL-separated blob. Passing that blob as a
   boxed Rex string copied it with `strlen`, discarding every name after the
   first — so `p.y` read as `nil` while `p.x` worked. The fix required adding a
   raw-pointer shim (`rex_cmm_cstr_raw`) and keeping the blob unboxed. This one
   bug caused a whole family of confusing symptoms and is documented in §3.3.

3. **Receiver type inference, enabling method calls.** The backend originally
   resolved `Type.method()` only when the receiver's *name* was literally the
   type name. Any real call — `p.len()`, `opt.is_some()` — failed. Adding a
   type-annotation scope parallel to the existing value scope made method
   resolution work without a full type checker.

4. **Fixing a path collision that made every second `build` fail.** The Cmm
   source and its executable collapsed onto the same filename, so the binary
   overwrote the source and the next build fed the binary to `gmm` as Cmm text.
   Found from a user report rather than by the test suite -- see 3.11, and 5.5
   for why the harness missed it.

5. **Eliminating cross-backend name drift.** The C and Cmm backends each had
   their own copy of the Rex-name → C-symbol table, and they had already
   diverged (`ui.grid` resolved to a nonexistent `rex_ui_grid`; the real symbol
   is `rex_ui_layout_grid`). Rather than patch the one name, both tables were
   extracted into `compiler/codegen/runtime_builtins.lua` so the class of bug
   cannot recur.

### 1.3 What is not done

No garbage collection (boxes are leaked); `spawn` unsupported; bonds/rollback/
temporal rejected; Linux only; external package members partial. Details in
§5.2.

---

## 2. Detailed Work Log

### Phase 0 — Feasibility spikes (before any backend code)

The central risk was whether Cmm could be made to work at all *without* the RTS.
Rather than start writing a backend and discover the answer later, I wrote small
standalone `.cmm` programs and compiled them with the bundled `gmm` directly.

**Spike 0.1 — return values.** Ordinary `return` from a Cmm function works, and
results are read from `R1`, `R2`, … Result: the calling convention is
workable.

**Spike 0.2 — Cmm → C calls.** `foreign "C" f(args)` works for `int`, `uint64_t`,
pointer, and `void` returns. **`double` and struct returns are broken** and cannot
be used. Consequence: the shim must box every value it returns into a `W_`
pointer, and unbox its arguments. This finding shaped the entire value
representation.

**Spike 0.3 — calling the other way.** C cannot call a Cmm function through the
C ABI. Confirmed by experiment, not assumption. This is the reason `spawn` is
permanently blocked without a trampoline.

**Spike 0.4 — `gmm` linking.** Compiling one Cmm file and linking it against
separately compiled C objects works. **No RTS is linked.** This is the property
the whole project rests on, and it was confirmed before any real code was
written.

**Spike 0.5 — goto and loops.** `goto` works, so `while` and `for` can be
lowered with explicit labels.

**Design decision — rejected: a C bridge / CPS.** An intermediate design
considered having C call into Cmm through a hand-rolled calling-convention shim,
or using continuation-passing to keep all control flow in C. Both were
**abandoned**: the first conflicts with the C ABI, the second with Cmm's stack
and register model. The abandoned prototype remains at
`/tmp/opencode/cmmtest/bridge.cmm` and must not be used as a starting point.

**Design decision — adopted: uniform boxed values.** Because `double` and struct
returns from `foreign` are broken, every value crossing the Cmm/C boundary is a
`W_` pointer to a heap `RexValue`. This makes the convention trivial to generate
and to debug, at the cost of a box allocation per operation.

### Phase 1 — The shim layer

**Step 1.1 — inventory the runtime.** Enumerated the public surface of
`rex/runtime_c/rex_rt.h`. Most entry points are `(...) -> RexValue`, which maps
almost perfectly onto a box-in/box-out shim.

**Step 1.2 — write `tools/gen_cmm_shim.py`.** A generator was written rather
than hand-writing 250 wrappers, because:
* it can re-derive the list when the runtime changes;
* it can read the real C signatures to know which functions return `void`
  (those need a *different* codegen call shape);
* it keeps the C and Cmm backends honest about which symbols exist.

Output: `rex/runtime_c/rex_cmm_shim.c`, `rex_cmm_shim.h`, and
`compiler/codegen/cmm_shim_table.lua`. Final counts: **243 generated wrappers**,
**19 void entry points** in the table.

**Step 1.3 — the void-table problem.** The first version hard-coded a list of
void functions in the Cmm backend. It immediately drifted from the real
signatures and produced wrong output for `collections` and `io`. Fixed by having
the generator *parse the C headers* and emit `cmm_shim_table.lua`, so the void
set is derived, never typed by hand. `collections` and `io` then matched.

**Step 1.4 — variadic `collections.vec_from(...)`.** This is variadic, so no
uniform wrapper exists. Rather than invent one, the Cmm backend lowers it to the
existing non-variadic builder sequence `rex_cmm_vec_begin` / `..._push` /
`rex_cmm_vec_end`.

### Phase 2 — gmm syntax conformance

Several Cmm syntax rules were learned the hard way, each by hitting a parser
error:

| Rule | Symptom when violated |
|---|---|
| Function definitions have **no return type** | parse error on `W_ f(...)` |
| Foreign calls require `()` **even with zero arguments** | parse/ICE on `foreign "C" f;` |
| `section "data"` accepts **one item per block** | parse error when two strings share a block |
| GHC's lexer reads `\x` as a **greedy** hex escape | silently wrong data: `"\x41BC"` swallows the `BC` |

The last one is worth calling out: it is a *silent* corruption, not an error.
The fix was to emit every byte as its own `\xNN` escape, which is unambiguous
adjacent to any other byte.

String emission became: one `section "data"` per string, body
`"\xNN\xNN...\x00"`.

### Phase 3 — Backend implementation (`cmm_codegen.lua`)

Built up incrementally, each step verified end-to-end:

* literals: `nil`, bool, numbers, strings
* identifiers, unary and binary operators
* `let` bindings and scoping; **function parameters must not be redeclared** in
  the body, because the signature already introduces them
* control flow: `if`/`else`, `while`, `for` (all `for` forms), `break`,
  `continue`, `return`
* functions and methods, `impl` blocks
* structs: construction, field read/write
* enums, including payload-carrying variants
* arrays, indexing, slicing
* collections, `use rex::…` modules
* `match` — both as a statement and as a tail expression
* `defer`
* `try` / the `?` propagate operator

**Loop lowering detail.** Cmm has no `for`, so all `for` forms lower to
`goto` + labels. Two subtleties were fixed: the test expression must be
evaluated *before every iteration* (not hoisted), and `continue` inside a C-style
`for` must reach the increment rather than jumping to the condition.

**Defers.** Initialised unconditionally at scope entry, rather than inferred from
the statements present.

### Phase 4 — CLI integration

**Step 4.1 — backend selection.** `Codegen.generate_cmm` exported from
`compiler/codegen/init.lua`; `--target c|cmm` threaded through `build` and
`run`.

**Step 4.2 — `find_gmm`.** Searches `$REX_GMM`, then `cmm/gmm` beside the repo
root, then `rex/cmm/gmm`.

**Step 4.3 — `compile_cmm`.** Invokes `gmm` with the platform sources and system
libraries, then links with the chosen C compiler.

**Step 4.4 — target-aware caching.** The build fingerprint now includes the
target, so a C build and a Cmm build of the same source do not collide.

**Step 4.5 — argument-order convention.** Discovered that
`run --target cmm file.rex` resolves the *project entry point* rather than the
named file. This is the CLI's pre-existing convention, not a new bug; documented
in the manual (§4.1) rather than "fixed", to avoid changing behaviour for
existing users.

### Phase 5 — The differential sweep

The decisive step: run **every** example under both targets and diff the output.
This turned "seems to work" into a number.

First full sweep: **`pass=19 bad=17 skip=1`**. The 17 failures became the work
queue, and each fix below was driven by a specific failure.

### Phase 6 — Bug-by-bug fixes

**Bug 1 — unsafe lazy caches (GHC register-allocation ICE).**
Caching a boxed `1` or a boxed string in a Cmm local and reusing it produced an
"uninitialised register" crash: the dominance analysis could not prove the cache
was live on every use path. Fix: remove the caches entirely. Every operation
emits its own `rex_cmm_mkbox`; only *data-section labels* are cached, and those
are compile-time constants. Cost: slightly more allocation; benefit: the ICE
class of failure is gone.

**Bug 2 — the `strlen` truncation (§3.3 below).** The most consequential bug.

**Bug 3 — use-after-free in `rex_cmm_struct_end`.**
`rex_struct_new` **retains** the field-name table pointer for the struct's
lifetime, so the shim's `free(names)` freed memory the runtime still pointed at.
Manifested as a segfault in `test_postfix_assign` and `test_compound_assign`.
Fix: deliberately leak the table (one small allocation per struct type, at type
construction). After the fix both tests matched.

**Bug 4 — `emit_function_body` Lua scoping.**
A forward declaration `local emit_function_body` was added before `emit_method`,
but the later definition was written `local function emit_function_body(...)`.
In Lua that creates a **new shadowing local** from the declaration onward, so
`emit_method` — defined in between — closed over the outer local, which was
still `nil`. Error: `attempt to call global 'emit_function_body' (a nil value)`.
Fix: define it as an *assignment* (`emit_function_body = function(...)`) so the
outer local is filled in.

**Bug 5 — receiver type inference.** See §3.4.

**Bug 6 — cross-backend name drift.** See §3.5.

**Bug 7 — multiple strings per data section.** Covered in Phase 2.

**Bug 8 — `try` / `?`.** The propagate operator needed an explicit early-return
path; `try.rex` then matched.

**Bug 9 — match as a tail expression.** A function whose body ended in `match`
returned nothing. Fixed by materialising the match result into a local and
returning it, including correct arm-binding. `test_wildcard_match.rex`,
`result.rex`, and `result_helpers.rex` then matched.

### Phase 7 — Test harness

`tools/test_cmm_parity.sh` was added, because an ad-hoc shell loop is not a
regression test.

Design decisions, each of which was a real source of false results during
development:

* **Reset filesystem state between the two runs.** `os_fs` initially reported a
  `DIFF` because the C run created `rex_data` and the Cmm run then found it
  already present (`created:` vs `exists:`). The script now scrubs state before
  each run.
* **Normalise timings.** `hello` reports `elapsed:`, which can never match
  exactly; such examples are classified `TIMING`, not `DIFF`.
* **Redirect stdin on *both* runs.** `xo` reads input; with the terminal attached
  the C run blocked until the 30 s timeout and exited 124.
* **Distinguish `KNOWN` from `FAIL`.** Unimplemented constructs are enumerated so
  that a *new* failure is never masked.

---

## 3. Issues Encountered & Resolved

### 3.1 GHC register-allocation / dominance crashes

**Symptom.** `Panic: ... register allocator ... uninitialised` or
`Dominance check failed`, non-deterministically, on programs that were
semantically correct.

**Diagnosis.** Lazy caching of boxed values in Cmm locals. A cache slot's
liveness depends on control flow the dominance checker reasons about, and the
box was *sometimes* produced and *sometimes* not.

**Resolution.** Delete the caches. Only immutable data-section labels are reused.
Never cache a runtime-computed value across statements.

### 3.2 `double` and struct returns from `foreign` calls are broken

**Symptom.** Arithmetic produced garbage or an ICE.

**Diagnosis.** Found by isolated spike, not by guessing: `foreign "C"` returning
a C `double` or a C struct does not work.

**Resolution.** Structural. Every value crossing the boundary is a `W_` pointer
to a boxed `RexValue`, so a shim returns a pointer (which does work) and the C
side unboxes/reboxes. Arithmetic happens in C on `RexValue`s, never in Cmm
registers.

### 3.3 Struct field names truncated at the first NUL — *the subtle one*

**Symptom.** A two-field struct returned correct values for the **first** field
and `nil` for the second:

```
$ ... --target cmm
3          # p.x      correct
Rex panic: mul expects numbers   # p.len() → self.y is nil
```

Because the first field was always right, this looked like an arithmetic bug
rather than a data bug, and it survived several rounds of misdiagnosis. A
minimised case produced `9nil` for `self.x * self.x + self.y`, which is what
finally localised it to field lookup.

**Root cause.** Field names are a single NUL-separated blob, `"x\0y\0\0"`. The
blob was being passed to the shim as a boxed Rex string. Boxing goes through
`rex_str`, which **copies using `strlen`** — so the copy was just `"x"`. The
shim then computed `names[1]` as `cursor + 2`, a pointer past the end of the
copy. A one-field struct worked, which is why the original smoke test passed.

**Resolution.** Added a raw-pointer shim:

```c
/* Pass a data-section string through unchanged. ... */
const char* rex_cmm_cstr_raw(W_ p) { return (const char*)p; }
```

and made `rex_cmm_struct_end` use it for the field-name blob. The codegen now
emits the data-section label directly (`rxr_s4 "ptr"`) instead of boxing it.

**Lesson.** Any NUL-containing data must bypass the boxing layer. This is now
called out in a comment at the emission site so it is not "simplified" back.

### 3.4 Method calls unresolvable on real receivers

**Symptom.** `unsupported call target (the Cmm target cannot resolve this
callee)` for `p.len()`, `opt.is_some()`; `enums.rex` and `structs.rex` failed
outright.

**Diagnosis.** `resolve_callee` only handled `Type.method()` — a member call
where the receiver's *identifier* is also a type name. Any method called on a
value (`p.len()`) fell through to the error.

**Resolution.** A type-annotation scope mirroring the existing value scope:

* `ctx.types` — a parallel stack of `Rex name → "struct:X" | "enum:X" | "num" |
  "bool" | "str" | "unknown"`.
* Annotations recorded on `let` (from the declared type, or inferred from a
  `Type{...}` / `Type.new(...)` / `Enum.Variant(...)` / `Enum.Variant` right-hand
  side), on every function parameter, and on `self` (as the `impl`'s own type).
* `receiver_named_type(expr)` walks identifiers, generic wrappers, and nested
  member access, resolving a field's declared type through the struct definition.

Deliberately *not* a full type checker — it records only what method resolution
needs. `self` being typed as the impl's type is what makes `self.x` resolvable
inside a method body.

The error message was also improved to name the method, so the next occurrence is
self-diagnosing:

```
the Cmm target cannot resolve this call target (method calls need a
resolvable receiver type): is_some
```

### 3.5 Link failure: `undefined reference to 'rex_cmm_ui_grid'`

**Symptom.** `xo` compiled and linked all the way to
`collect2: error: ld returned 1 exit status`, with the only real diagnostic
being one undefined symbol. No Lua error, no Cmm error.

**Diagnosis.** The Cmm `ui` module table was built by concatenating
`"rex_ui_" .. name`, so `grid` became `rex_ui_grid`. The real runtime symbol is
`rex_ui_layout_grid` (as the C backend already had it). This was a *link-time*
failure caused by a *compile-time* table divergence — the worst failure mode,
because nothing in the compiler complained.

**Resolution — class fix, not name fix.** Patching `grid` would have left the
other ~180 entries free to drift. Instead both backends' tables were extracted
into a new shared module, `compiler/codegen/runtime_builtins.lua`, and both now
`require` it. The C backend's inline `local ctx = { builtins = ..., module_builtins
= ... }` was replaced with references to the shared tables.

To confirm the extraction was lossless, the two tables were diffed
programmatically. That diff found *more* drift than the one visible failure:

| Module | Cmm-only (wrong) | C-only (missing) |
|---|---|---|
| `ui` | `layout_row`, `layout_column`, `layout_grid` | `row`, `column`, `grid` |
| `result` | — | `Ok`, `Err` |
| `collections` | `get`, `slice` | `vec_from` |
| `audio` | `get_volume` | `volume` |
| `log` | `get_level` | `level` |

Most were harmless (the Cmm-only spellings happened to be valid aliases, and
`vec_from` was special-cased in Phase 1), but the shared module removes the
entire category.

Four bare builtins the C backend emits directly rather than through its table are
still added by the Cmm backend: `is_truthy`, `panic`, `tag_is`, `result_is`.

### 3.6 Struct use-after-free

See Bug 3 in §2, Phase 6. Root cause: the runtime retains the field-name table
pointer; the shim freed it.

### 3.7 `os_fs` false DIFF

Not a backend bug — a **test-harness** bug. The C run created `rex_data`, so the
Cmm run observed pre-existing state. Fixed by scrubbing state between runs; `os_fs`
then passed. Recorded because it demonstrates that a differential harness can
manufacture failures that look like real ones.

### 3.8 Lua forward-declaration shadowing

See Bug 4 in §2, Phase 6. Worth a line in any Lua codebase: `local function f`
after `local f` **shadows**; use `f = function` to assign the forward-declared
local.

### 3.9 Toolchain documentation drift

`rex --help` does not list `--target cmm` (recorded as limitation 7). The flag
works; the help text was simply never updated. The manual documents the real
flags, and the stale help is logged as a known gap rather than silently ignored.

### 3.10 Items in the original brief that do not exist in this repository

Recorded explicitly so they are not mistaken for missing work:

* **`cmmath` / `stdc--`** — these are part of the upstream C-minus-minus
  distribution. `gmm` bundles and extracts them (`stdc--.h`, `cmmath.h`,
  `cmmath.c`, `ret.h`) into a temp directory at compile time. The Rex Cmm backend
  **does not use them**; generated code imports only `Cmm.h`, because all Rex
  semantics come from `rex/runtime_c`. They were not added by this project and are
  not required to use it.
* **"NCG isolation"** — there is no such feature here. The Cmm backend does use
  the native code generator (it invokes `gmm` directly, and `gmm` has an
  optional `-llvm` flag), but no isolation layer was built. The `NCG` mentions in
  `cmm/README.md` and `cmm/ret.md` are upstream prose.
* **make / xmake** — there is no make-based build system. Build orchestration is
  the Rex CLI (`build`, `run`, `bench`), and the only generator is
  `python3 tools/gen_cmm_shim.py`. No `Makefile`, `xmake.lua`, or `CMakeLists.txt`
  exists in the repository.

### 3.11 Cmm source and executable shared one path — *found in the field*

**Symptom.** `run --target cmm` worked, but a second consecutive `build
--target cmm` on the same example failed:

```
$ luajit compiler/cli/rex.lua build examples/hello.rex --target cmm
ghc-9.10.3: fd:18: hGetContents: invalid argument
  (cannot decode byte sequence starting from 145)
`gcc' failed in phase `C-- C pre-processor'. (Exit code: 2)
```

Note the deceptive part: the *first* build succeeded, and `run` kept working.

**Diagnosis.** `default_exe_path` derived the executable path by stripping a
`.c` suffix:

```lua
local base = out:gsub("%.c$", "")     -- anchored at end
```

The pattern `%.c$` requires `.c` at the very end of the string.
`"build/main.cmm"` ends in `mm`, so it **does not match** and the path is
returned unchanged. For the Cmm target that made the two paths identical:

```
c_out (Cmm source) = build/main.cmm
out   (executable) = build/main.cmm      <-- same file
```

The failure sequence is then:

1. Build #1 writes Cmm **text** to `build/main.cmm`.
2. `gmm -o build/main.cmm build/main.cmm …` reads that text and **overwrites the
   same path** with the linked executable.
3. Build #2's incremental check finds the fingerprint file current, so it does
   **not** regenerate the Cmm source — leaving an ELF binary sitting at
   `build/main.cmm`.
4. `gmm` is handed the ELF binary as its Cmm input. Its C-preprocessor phase
   decodes the input as text, hits a non-UTF-8 byte (`0x91`, common in ELF
   padding), and dies.

**Why `run` escaped it.** `run` has the identical latent collision, but it
allocates a fresh `build/run/<name>_<id>` directory for every invocation, so it
never re-enters a path that already holds a linked binary. The bug was therefore
only reachable through `build`, which reuses one path. This is why the failure
looked inconsistent and intermittent rather than deterministic.

**Resolution.** Strip the source extension correctly, longest first:

```lua
local base = out:gsub("%.cmm$", ""):gsub("%.c$", "")
```

Verified: builds #1–#4 now behave correctly (#1 compiles, #2–#4 cached), the
executable lands at `build/main`, and the C-- source stays readable at
`build/main.cmm`. The C target is unaffected (`build/main.c` → `build/main` as
before). `run` and `bench` also lose their latent collision.

**Lesson.** Anchored-extension stripping (`%.c$`) is silently wrong for any
longer compound extension. Anywhere an extension is derived, test the *longest*
case too — `hello.c` and `hello.cmm` together, not just one of them.

---

## 4. Files Added / Modified

### Added

| File | Role |
|---|---|
| `rex/compiler/codegen/cmm_codegen.lua` | the Cmm backend |
| `rex/compiler/codegen/runtime_builtins.lua` | shared Rex-name → C-symbol tables |
| `rex/compiler/codegen/cmm_shim_table.lua` | **generated** — which shims return void |
| `rex/runtime_c/rex_cmm_shim.c` | **generated** — 243 C shim wrappers + manual ones |
| `rex/runtime_c/rex_cmm_shim.h` | **generated** — shim declarations |
| `tools/gen_cmm_shim.py` | generator for the three files above |
| `tools/test_cmm_parity.sh` | differential C-vs-Cmm test suite |

### Modified

| File | Change |
|---|---|
| `rex/compiler/cli/rex.lua` | `--target c\|cmm`, `find_gmm()`, `compile_cmm()`, target-aware build cache |
| `rex/compiler/codegen/init.lua` | export `Codegen.generate_cmm` |
| `rex/compiler/codegen/c_codegen.lua` | use the shared builtin tables (behaviour-preserving refactor) |

### Untouched

`rex/runtime_c/rex_rt.{c,h}`, the lexer, parser, typechecker, AST, and all 37
examples. The two targets share one runtime by design, so the runtime was never
forked.

---

## 5. Current Project State & Next Steps

### 5.1 Functional today

Verified by `tools/test_cmm_parity.sh`, output-identical to the C target:

* literals, operators, string concatenation and interpolation
* `let`/scoping, functions, recursion, `impl` methods
* structs (construction, field read/write, methods on `&self`)
* enums, including payload-carrying variants and methods
* `if`/`else`, all `for` forms, `while`, `break`, `continue`
* arrays, indexing, slicing
* `match` as both statement and tail expression, with arm binding
* `defer`
* `try` and the `?` propagate operator
* `use rex::io`, `rex::collections`, `rex::math`, `rex::time`, `rex::os`,
  `rex::fs`, and the rest of the standard module surface
* UI, audio, and network subsystem linkage

Confirmed equal to the C target: `hello`, `loops`, `structs`, `enums`,
`collections`, `io`, `result`, `result_helpers`, `try`, `test_wildcard_match`,
`test_postfix_assign`, `test_compound_assign`, `test_struct_lit`,
`test_nested_assign`, `xo`, `os_fs`, and the remainder of the passing set.

### 5.2 Known gaps

| Gap | Impact | Difficulty |
|---|---|---|
| **No GC — boxes are leaked** | unbounded memory in long-running programs | **High; should be next** |
| `spawn` unsupported | no concurrency | High — needs a trampoline + per-thread stacks |
| `Bond`, `Commit`, `Rollback` rejected | no bond/rollback programs | Medium |
| `WithinBlock`, `DuringBlock`, `DebugOwnership` rejected | temporal/ownership programs | Medium |
| `os.args` not wired | no process arguments | Low |
| External package members partial | multi-file user packages | Medium |
| Non-Linux unvalidated | portability | Medium |
| `rex --help` omits `--target` | discoverability only | Trivial |
| Generated parameter names unmangled | potential keyword collision | Low |
| ~~`build` writes the executable to `build/main.cmm`~~ | **fixed** — see §3.11; this had made every second build fail | — |

### 5.3 Recommended order of work

1. **Garbage collection / box reclamation.** The only gap that affects the
   correctness of long-running programs. Everything else is a missing feature;
   this is a resource-exhaustion bug. Start by measuring allocation on
   `benchmark_0` to confirm the leak profile, then decide between a
   reference-counting scheme (matches the `&`/`&mut` discipline the language
   already has) and a mark-sweep collector over the Cmm stack plus shim-held
   roots. The latter is harder but avoids pushing reference counting into
   generated code.
2. **Wire `os.args`** and **update `rex --help`** — both small, both improve
   perceived completeness.
3. **`spawn` via a trampoline.** Requires a C-callable entry that sets up a Cmm
   stack for the new thread, then runs the body. Bounded and well-defined; do it
   after GC so the design accounts for GC roots on foreign stacks.
4. **Temporal/ownership constructs**, then **bonds/rollback**.
5. **Broaden the type-annotation layer** into something closer to a real
   inference pass, so method resolution stops depending on syntactic cues.
6. **Portability:** validate macOS, then Windows.
7. **Naming hygiene:** mangle generated identifiers against Cmm keywords/macros
   and add a test that exercises it.

### 5.4 Why the test harness missed the build bug

`tools/test_cmm_parity.sh` reported a green `pass=31 fail=0` while `build` was
broken, because the harness only ever exercises `run`:

```sh
luajit compiler/cli/rex.lua run "$file" --target cmm
```

`run` allocates a fresh `build/run/<name>_<id>` directory per invocation, so it
can never reuse a path that already holds a linked binary. The collision was
therefore unreachable through `run` and only reachable through `build`, which
reuses one path.

**Correction made.** The harness now also drives `build` twice in a row for
every example, which is the exact sequence that failed. The regression is
guarded rather than merely noted.

The general lesson: a differential harness only covers the paths it actually
executes. `run` and `build` share a code path for codegen but not for artifact
placement, so "the suite is green" was never evidence that `build` worked.

### 5.5 Process improvements worth keeping

* The **differential sweep** was the single highest-value technique. It turned
  vague "seems to work" into a count, and every count exposed a real bug.
* **Isolate before diagnosing.** Bugs 1, 2, and 3.3 all resisted reasoning about
  the full program and fell apart immediately once reduced to a minimal `.cmm`
  or `.rex` file.
* **When two artifacts must agree, share one source of truth.** Bugs 3.5 and the
  void table (§Phase 1.3) were both divergence-between-copies, and both were
  fixed by generating from a single origin rather than by syncing.
* **Test harnesses have bugs too.** §3.7 manufactured a failure that looked like
  a backend bug. Normalise inputs and reset shared state before believing a diff.
