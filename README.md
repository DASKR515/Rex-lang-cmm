# Rex → C-- (Cmm) Backend — User Manual

The **Cmm target** compiles Rex programs to standalone C-- and links them into
plain native executables **without the GHC Runtime System (RTS)**.

This document covers what the backend is, how to install it, how to compile and
run programs through it, and how to verify a working install.

---

## 1. Project Overview

### 1.1 What this is

Rex is a small statically-typed language whose compiler is written in Lua and run
with `luajit`. The compiler has two interchangeable backends:

| Target | Flag | Pipeline | Runtime |
|---|---|---|---|
| C (default, reference) | *(none)* | `rex → C → clang/gcc` | `rex/runtime_c` |
| **C-- / Cmm** | `--target cmm` | `rex → C-- → gmm → clang/gcc` | `rex/runtime_c` + generated C shim |

Both targets share **the same C runtime** and **the same name tables**, so a
program that behaves correctly under `--target c` is expected to behave
identically under `--target cmm`. That equivalence is enforced mechanically by
the differential test suite (see §5).

The Cmm backend exists because C-- is a portable low-level intermediate: the same
source can be handed to a native code generator, to LLVM, or to an interpreter.
By keeping the RTS out of the picture, the output is a self-contained executable
with no Haskell runtime to ship.

### 1.2 Core architecture

```
   program.rex
        │
        ▼
   ┌─────────────┐
   │ lexer       │
   │ parser      │   rex/compiler/{lexer,parser}
   │ typechecker │
   └──────┬──────┘
          │  AST
          ▼
   ┌─────────────┐
   │  cmm_codegen│   rex/compiler/codegen/cmm_codegen.lua
   └──────┬──────┘
          │  main.cmm   (C-- text)
          ▼
   ┌─────────────┐
   │ gmm  v3.0   │   cmm/gmm
   │ (NCG)       │   → object files
   └──────┬──────┘
          │
          ▼
   clang/gcc  ── +  rex/runtime_c/*.c        (the Rex C runtime)
             ── +  rex/runtime_c/rex_cmm_shim.c  (generated C shim)
             │
             ▼
       native executable   (no RTS)
```

**Key architectural decisions**

* **Cmm calls C, never the reverse.** The Cmm ABI passes arguments in registers
  and returns results in `R1`, `R2`, … There is no C-ABI-compatible way to call
  a Cmm function from C. Therefore *every* runtime operation is reached through a
  small **C shim function** that Cmm can call as a leaf. There are 243
  auto-generated shim wrappers plus a handful of hand-written ones.

* **One uniform value representation.** A Rex value is a pointer (`W_`) to a
  heap-allocated, tagged `RexValue`. Every Cmm local, parameter, and return value
  has this type. Arithmetic, strings, structs, collections, and enums are all
  operations on these boxes, which keeps the calling convention trivial and
  removes any need for the compiler to reason about Cmm's type-directed
  calling conventions.

* **Manual stack.** `gmm` inserts no stack checks of its own, so `main` allocates
  a 64 MiB region and points the Cmm globals at it:

  ```
  Sp    = base + size;   // grow down
  SpLim = base;
  ```

  The C shim then sets up a `setjmp`/`longjmp` landing pad so a Rex `panic`
  unwinds to `main` instead of aborting.

* **No GC yet.** Boxes are intentionally leaked for now. This is correct — every
  program in the test suite produces byte-identical output to the C target — but
  it means long-running programs grow without bound. See §6.

* **Raw pointers for NUL-separated data.** Struct field names are stored as a
  single `"x\0y\0\0"` blob. This blob cannot travel as a boxed Rex string,
  because boxing copies with `strlen` and would truncate it after the first name.
  It is passed through a dedicated raw-pointer shim instead (§4.3, bug 2).

### 1.3 Repository layout

```
Rex-language/
├── rex/                              the Rex compiler
│   ├── compiler/
│   │   ├── cli/rex.lua               CLI: build, run, bench, test, fmt, lint
│   │   ├── codegen/
│   │   │   ├── c_codegen.lua         C backend (reference semantics)
│   │   │   ├── cmm_codegen.lua       Cmm backend
│   │   │   ├── runtime_builtins.lua  shared Rex-name → C-symbol tables
│   │   │   ├── cmm_shim_table.lua    generated: which shims return void
│   │   │   └── init.lua              backend selection (Codegen.generate_cmm)
│   │   ├── lexer/  parser/  typechecker/  ast/
│   ├── runtime_c/
│   │   ├── rex_rt.c / rex_rt.h       the shared Rex C runtime
│   │   ├── rex_cmm_shim.c / .h       GENERATED C shims for the Cmm target
│   │   └── rex_ui.c, rex_audio.c, …  optional subsystem runtimes
│   ├── examples/*.rex                37 conformance programs
│   └── build/                        output directory
├── cmm/
│   ├── gmm                           bundled gmm v3.0 driver (C-- → object)
│   ├── README.md, ret.md             Cmm language notes
│   └── *.cmm                         standalone Cmm samples
├── tools/
│   ├── gen_cmm_shim.py               GENERATES rex_cmm_shim.{c,h} + shim table
│   └── test_cmm_parity.sh            differential C-vs-Cmm test suite
└── log.md              this manual and the dev log
```

---

## 2. Requirements & Prerequisites

### 2.1 Verified configuration

| Component | Version | Notes |
|---|---|---|
| OS | Linux x86-64 | only platform validated so far |
| `luajit` | 2.1 | runs the Rex compiler |
| C compiler | `gcc` or `clang` | links the runtime and shim |
| `python3` | 3.6+ | only needed to **regenerate** the shim |
| `gmm` | v3.0 | **bundled** at `cmm/gmm`; no separate install |
| `ghc` | any | deps gmm needed |
* link Dowaload [gmm](https://github.com/DASKR515/C-minus-minus/releases)
The bundled `cmm/gmm` is a prebuilt standalone driver, so **GHC does not need to
be installed on your machine**. It was built against host GHC 9.10.3, but that
toolchain is not required at runtime.

### 2.2 Why gmm ships its own headers

`gmm` bundles `stdc--.h`, `cmmath.h`, `cmmath.c`, and `ret.h`, extracting them
into a temporary directory at compile time. Those belong to the upstream
C-minus-minus distribution, not to this project.

The Rex Cmm backend **deliberately does not use them** — generated code imports
only `Cmm.h`. All Rex semantics come from the C runtime in `rex/runtime_c`, which
is what lets the two targets share one implementation. You do not need to install
or configure `stdc--.h` or `cmmath.h` to use this backend.

### 2.3 Optional: using your own gmm

If you have a different `gmm` build, point the compiler at it:

```sh
export REX_GMM=/path/to/gmm
```

The compiler searches, in order: `$REX_GMM`, then `cmm/gmm` next to the
repository root, then `cmm/gmm` inside `rex/`.

### 2.4 Platform libraries

`compile_cmm` links the same platform sources and system libraries the C target
uses — on Linux that is X11, ALSA (`-DREX_AUDIO_HAS_ALSA`), and friends. UI and
audio examples therefore need those development headers present. If you only run
console programs, they are still linked but never called.

---

## 3. Installation & Setup

There is no build step for Rex itself; it is interpreted Lua.

```sh
git clone <this-repository>
cd Rex-language
```

Confirm the toolchain is visible:

```sh
./cmm/gmm -h          # prints gmm v3.0 usage
```

### 3.1 Make the shim files executable-optional

The shims `rex/runtime_c/rex_cmm_shim.c` and `rex_cmm_shim.h` are **checked in**,
so a fresh clone works immediately. Regenerate them only if you change
`rex/runtime_c/rex_rt.h`:

```sh
python3 tools/gen_cmm_shim.py
```

Expected output:

```
generated 243 wrappers
wrote rex/compiler/codegen/cmm_shim_table.lua (19 void entry points)
manual (skipped): rex_collections_vec_from, rex_num, rex_os_set_args, ...
```

The generator is idempotent — re-running it on unchanged input produces an
identical file.

### 3.2 Optional: make `gmm` findable

Not required, but convenient:

```sh
ln -s "$(pwd)/cmm/gmm" ~/.local/bin/gmm && export PATH="$HOME/.local/bin:$PATH"
```

---

## 4. Usage Guide

### 4.1 The one rule about argument order

The input file must come **before** the options:

```sh
# correct
rex run examples/hello.rex --target cmm

# WRONG — this resolves the project entry point instead and ignores the file
rex run --target cmm examples/hello.rex
```

This is the CLI's existing convention and applies to every subcommand.

### 4.2 Running a program

The compiler is invoked from inside `rex/`, because its module path is relative:

```sh
cd rex
export LUA_PATH="./?.lua;./?/init.lua;;"
```

**Compile and run in one step:**

```sh
luajit compiler/cli/rex.lua run examples/hello.rex --target cmm
```

**Compare against the reference C target:**

```sh
luajit compiler/cli/rex.lua run examples/hello.rex            # C
luajit compiler/cli/rex.lua run examples/hello.rex --target cmm   # Cmm
```

**Emit C-- without compiling it**, to read the generated code:

```sh
luajit compiler/cli/rex.lua build examples/hello.rex --target cmm --no-native
less build/main.cmm
```

**Produce a native binary:**

```sh
luajit compiler/cli/rex.lua build examples/loops.rex --target cmm
./build/main          # for `run`; see the note on output naming below
```

> **Output-naming note.** For the Cmm target the CLI's default artifact path is
> `build/main.cmm`, and that path ends up holding the *linked executable*, not
> the C-- source. With `--no-native` it holds the C-- text instead. This is a
> cosmetic wart inherited from the C target's `build/main.c`; pass `--out` or
> `--c-out` if the name matters to you.

### 4.3 A worked example

`examples/structs.rex`:

```rex
use rex::io

struct Point { x: f64, y: f64 }

impl Point {
    fn len(&self) -> f64 {
        return sqrt(self.x * self.x + self.y * self.y)
    }
}

fn main() {
    let p = Point.new(3, 4)
    println(p.x)
    println(p.len())
}
```

Compile and run under both targets:

```sh
$ luajit compiler/cli/rex.lua run examples/structs.rex
3
5

$ luajit compiler/cli/rex.lua run examples/structs.rex --target cmm
3
5
```

To see what the Cmm backend produced:

```sh
$ luajit compiler/cli/rex.lua build examples/structs.rex --target cmm --no-native
$ grep -n "rxr_m_Point_len" -A 12 build/main.cmm
```

which yields roughly:

```cmm
rxr_m_Point_len(W_ self) {
    W_ rxr_str1;
    W_ rxr_r2;
    ...
    (rxr_str1) = foreign "C" rex_cmm_str_raw(rxr_s1 "ptr");
    (rxr_r2) = foreign "C" rex_cmm_struct_get(self, rxr_str1);
    (rxr_r5) = foreign "C" rex_cmm_mul(rxr_r2, rxr_r4);
    ...
    return (rxr_ret);
}
```

Note the `foreign "C"` calls: each one is a C shim that boxes its arguments,
performs the operation on real `RexValue`s, and returns a fresh box.

### 4.4 Hand-written C-- with gmm

The Rex CLI is a convenience. `gmm` compiles any `.cmm` file directly, which is
how the `cmm/*.cmm` samples are built:

```sh
./cmm/gmm -o hello cmm/hello_print.cmm
./hello
```

`gmm` also reads a `conf.hmm` project file and understands `-b` (build), `-r`
(run), `-br` (build and run), `-libs`, `-keep-obj`, `-llvm`, and `-rts`. See
`./cmm/gmm -h` for the full list.

### 4.5 Useful options

| Option | Effect |
|---|---|
| `--target cmm` | select the Cmm backend (`--target c` is the default) |
| `--no-native` | stop after generating source; do not invoke `gmm`/the C compiler |
| `--c-out <path>` | choose the output path |
| `--cc <compiler>` | pick `gcc`, `clang`, or `zig cc` |
| `--mode release\|debug` | optimisation mode |
| `REX_GMM=<path>` | override the `gmm` driver |
| `REX_BUILD_DIR=<path>` | relocate the build directory |
| `cmm_stack_bytes=<n>` | code-generator option; stack size, default 64 MiB |

---

## 5. Quick Test & Verification Summary

### 5.1 The one-command check

```sh
./tools/test_cmm_parity.sh
```

This compiles and runs **every** `rex/examples/*.rex` under both backends and
compares the output, so it verifies the compiler, `gmm`, the C runtime, the shim,
and your C compiler in one shot.

Expected result on a healthy install:

```
=== pass=31 fail=0 known=6 ===
```

`fail=0` is the pass condition. The script exits non-zero if anything fails, so
it drops straight into CI.

### 5.2 Reading the output

| Line | Meaning |
|---|---|
| *(nothing)* | passed — output was byte-identical to the C target |
| `DIFF <name>` | both targets ran but produced different output — **a failure** |
| `FAIL <name>` | the Cmm target crashed or refused to compile — **a failure** |
| `KNOWN <name>` | a construct the Cmm backend has not implemented yet |
| `TIMING <name>` | differs only in reported elapsed times |
| `SKIP <name>` | the example does not run under the C target either, so there is nothing to compare |

The `KNOWN` cases are intentional and enumerated in the script, kept in step with
the `UNSUPPORTED` table in `cmm_codegen.lua`:

| Example | Unimplemented construct |
|---|---|
| `bonds_test`, `test_rollback_correct`, `test_rollback_error` | `Bond` |
| `ownership_thread_safe` | `DebugOwnership` |
| `simple_temporal` | `WithinBlock` |
| `spawn` | `Spawn` |

A **new** example that fails is reported as `FAIL`, so the supported surface
cannot regress silently.

### 5.3 Testing a single example

```sh
./tools/test_cmm_parity.sh hello loops structs enums
```

### 5.4 The 60-second smoke test

If you just want to know the toolchain is wired up:

```sh
cd rex
export LUA_PATH="./?.lua;./?/init.lua;;"

# 1. the reference target works
luajit compiler/cli/rex.lua run examples/hello.rex

# 2. the Cmm target produces the same thing
luajit compiler/cli/rex.lua run examples/hello.rex --target cmm

# 3. control flow, arrays, slicing, and collection iteration
luajit compiler/cli/rex.lua run examples/loops.rex --target cmm

# 4. structs and methods, including float arithmetic
luajit compiler/cli/rex.lua run examples/structs.rex --target cmm

# 5. enums with payloads
luajit compiler/cli/rex.lua run examples/enums.rex --target cmm
```

Expected output for steps 2–5:

| Example | Output |
|---|---|
| `hello` | `Hello from Rex` + an `elapsed:` line (timing varies) |
| `loops` | `0 1 2 0 1 2 4 5 6 20 10 20 30 done` |
| `structs` | `5` then `13.416407864999` |
| `enums` | `true false value = 7 empty` |

If `hello` and `loops` both work, the frontend, the Cmm backend, `gmm`, the shim,
and the C runtime are all functioning.

### 5.5 Quick benchmark

```sh
cd rex
luajit compiler/cli/rex.lua bench examples/benchmark.rex
luajit compiler/cli/rex.lua bench examples/benchmark.rex --target cmm
```

`bench` runs the program five times and reports `avg_ms` / `min_ms` / `max_ms`.
Both targets are supported; the Cmm target currently benchmarks slightly faster
than the C target on this example, though that is a single data point on one
machine and should not be treated as a general result.

---

## 6. Known Limitations

These are real and deliberate. None of them affect the 31 passing examples.

1. **No garbage collection.** Every boxed value is leaked for the life of the
   process. Correct, but unbounded in long-running or allocation-heavy programs.
   This is the single most important thing to fix next.
2. **`spawn` is not supported.** C cannot call Cmm functions through the C ABI,
   and a fresh OS thread has no initialised Cmm stack. Supporting it needs a
   trampoline plus per-thread stacks.
3. **Bonds, rollback, and temporal/ownership directives** are rejected with a
   clear error naming the construct.
4. **`os.args` is not wired through.** The generated `main` takes no arguments,
   so process arguments are unavailable.
5. **External package members are only partially resolved.** Single-file
   compilation with `use rex::<module>` is fully supported; user-written
   multi-file packages are partial and untested.
6. **Linux only.** macOS and Windows library sets are written but unvalidated.
7. **The CLI's `--help` text is stale** — it does not yet list `--target cmm`,
   although the flag works. Passing an unknown flag to `build`/`run` is still
   honoured.
8. **Generated parameter names are unmangled.** A Rex identifier that collides
   with a Cmm keyword or macro would need renaming; the suite does not currently
   test for that.

---

## 7. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `module 'compiler.ast' not found` | You are not in `rex/`, or `LUA_PATH` is unset. `cd rex` and export `LUA_PATH="./?.lua;./?/init.lua;;"`. |
| Command ignores the file you named | Put the input **before** the options (§4.1). |
| `the Cmm target cannot resolve this call target` | A method call on a receiver whose type could not be inferred. The message names the method. |
| `the Cmm target does not support X yet` | An unimplemented construct; X is named in the message and listed in §5.2. |
| `undefined reference to 'rex_cmm_...'` | The shim is stale. Run `python3 tools/gen_cmm_shim.py`. |
| `Rex panic: ...` at runtime | A genuine Rex-level error. Compare against the C target to see whether it is a backend bug or the program's fault. |
| Linker errors about `X11` / `asound` | Install the X11 and ALSA development headers. |
| `gmm: command not found` | `cmm/gmm` is missing or not executable; set `REX_GMM`. |

---

## 8. Where the work is recorded

`log.md` in the repository root is the chronological development log: what was
built, in what order, every bug hit, and how each was diagnosed and fixed. It is
the right place to look for the *reason* behind a design choice documented here.

For the Cmm language itself, see `cmm/README.md` and `cmm/ret.md`.
