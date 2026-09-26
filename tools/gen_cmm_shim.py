#!/usr/bin/env python3
"""Generate the Cmm FFI shim layer for the Rex Cmm code generator.

The Cmm backend cannot receive C `double` or struct return values, and it
represents every Rex value as a `W_` pointer to a heap-allocated `RexValue`
box.  This script reads `rex/runtime_c/rex_rt.h` and emits, for every runtime
entry point, a `rex_cmm_*` wrapper that:

  * takes and returns `W_` boxes only,
  * boxes/unboxes at the boundary,
  * passes real C `double`/`int` values for scalar parameters.

Functions with signatures that cannot be mechanically translated (raw
pointers, arrays, function pointers) are listed in MANUAL below and are
emitted verbatim from a hand-written section instead.

Usage:  python3 tools/gen_cmm_shim.py
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEADER = os.path.join(ROOT, "rex", "runtime_c", "rex_rt.h")
OUT_C = os.path.join(ROOT, "rex", "runtime_c", "rex_cmm_shim.c")
OUT_H = os.path.join(ROOT, "rex", "runtime_c", "rex_cmm_shim.h")
OUT_LUA = os.path.join(ROOT, "rex", "compiler", "codegen", "cmm_shim_table.lua")

# Functions whose C signatures cannot be translated by the generic rules
# below, either because they take raw pointers/arrays or because they are
# constructors that need a friendlier Cmm-side API.  Their bodies live in
# MANUAL_BODIES below.  Keeping this list explicit means an unhandled
# signature is a hard error rather than silently miscompiled output.
MANUAL = {
    "rex_num",                    # takes double
    "rex_ptr",                    # takes void*
    "rex_ref",                    # takes RexValue*
    "rex_ref_mut",                # takes RexValue*
    "rex_struct_new",             # (const char*, const char**, RexValue*, int)
    "rex_struct_get",             # (RexValue, const char*)
    "rex_struct_set",             # (RexValue, const char*, RexValue)
    "rex_tuple_new",              # (int, RexValue*)
    "rex_collections_vec_from",   # (int, RexValue*)
    "rex_os_set_args",            # (int, char**)
    "rex_spawn",                  # (RexSpawnFn, void*)
}

# Hand-written bodies, keyed by runtime function name.  `%s` is unused; the
# strings are emitted verbatim.
MANUAL_BODIES = {
    "rex_num": """
/* Cmm can pass a real `double` as a foreign argument (only *returns* are
 * broken), so numeric literals are built here from a genuine double. */
W_ rex_cmm_num(double n)
{
    return rex_cmm_mkbox(rex_num(n));
}
""",
    "rex_str": """
/* Build a Rex string from a *raw* C string literal in the Cmm data
 * section.  The generic `rex_cmm_str` wrapper takes an already-boxed Rex
 * string, so string literals need this separate raw entry point. */
W_ rex_cmm_str_raw(W_ s)
{
    return rex_cmm_mkbox(rex_str((const char*)s));
}
""",
    "rex_ptr": """
W_ rex_cmm_ptr(W_ p)
{
    return rex_cmm_mkbox(rex_ptr(p));
}
""",
    "rex_ref": """
/* A reference is a box that points at another box. */
W_ rex_cmm_ref(W_ addr)
{
    return rex_cmm_mkbox(rex_ref((RexValue*)addr));
}
""",
    "rex_ref_mut": """
W_ rex_cmm_ref_mut(W_ addr)
{
    return rex_cmm_mkbox(rex_ref_mut((RexValue*)addr));
}
""",
    "rex_struct_new": """
/* Struct construction is exposed as a builder because the C entry point
 * takes a `const char**` field-name table that cannot be built conveniently
 * from Cmm.  The generated code pushes one boxed value per field and then
 * calls rex_cmm_struct_end with a NUL-separated field-name blob. */
W_ rex_cmm_struct_begin(void)
{
    RexValue* values = NULL;
    size_t count = 0;
    size_t cap = 0;
    W_ b = malloc(sizeof(void*) * 3);
    if (!b) {
        rex_panic("rex: out of memory building a struct");
    }
    ((W_*)b)[0] = (W_)values;
    ((W_*)b)[1] = (W_)count;
    ((W_*)b)[2] = (W_)cap;
    return b;
}

void rex_cmm_struct_push(W_ builder, W_ value)
{
    W_* b = (W_*)builder;
    RexValue* values = (RexValue*)((W_*)b)[0];
    size_t count = (size_t)((W_*)b)[1];
    size_t cap = (size_t)((W_*)b)[2];
    if (count == cap) {
        size_t next = cap ? cap * 2 : 8;
        RexValue* grown = (RexValue*)realloc(values, next * sizeof(RexValue));
        if (!grown) {
            rex_panic("rex: out of memory building a struct");
        }
        values = grown;
        ((W_*)b)[0] = (W_)values;
        ((W_*)b)[2] = (W_)next;
    }
    values[count] = rex_cmm_val(value);
    ((W_*)b)[1] = (W_)(count + 1);
}

W_ rex_cmm_struct_end(W_ builder, W_ name, W_ field_names)
{
    W_* b = (W_*)builder;
    RexValue* values = (RexValue*)((W_*)b)[0];
    size_t count = (size_t)((W_*)b)[1];
    const char* blob = rex_cmm_cstr_raw(field_names);
    const char* cursor = blob;
    const char** names = NULL;
    size_t i;
    W_ result;
    if (count) {
        names = (const char**)malloc(count * sizeof(char*));
        if (!names) {
            rex_panic("rex: out of memory building a struct");
        }
        for (i = 0; i < count; i++) {
            names[i] = cursor;
            cursor += strlen(cursor) + 1;
        }
    }
    result = rex_cmm_mkbox(rex_struct_new(rex_cmm_cstr(name), names, values, (int)count));
    /* `rex_struct_new` stores the field-name table by reference rather than
     * copying it, and `s->fields` stays live for the struct's whole lifetime.
     * Freeing it here would leave every later `rex_struct_get`/`set` reading
     * freed memory, so the table is intentionally retained. */
    free(values);
    free(builder);
    return result;
}
""",
    "rex_struct_get": """
W_ rex_cmm_struct_get(W_ obj, W_ field)
{
    return rex_cmm_mkbox(rex_struct_get(rex_cmm_val(obj), rex_cmm_cstr(field)));
}
""",
    "rex_struct_set": """
void rex_cmm_struct_set(W_ obj, W_ field, W_ value)
{
    rex_struct_set(rex_cmm_val(obj), rex_cmm_cstr(field), rex_cmm_val(value));
}
""",
    "rex_tuple_new": """
/* Same builder shape as structs, for `rex_tuple_new`. */
W_ rex_cmm_tuple_begin(void)
{
    W_ b = rex_cmm_struct_begin();
    return b;
}

W_ rex_cmm_tuple_end(W_ builder)
{
    W_* b = (W_*)builder;
    RexValue* values = (RexValue*)((W_*)b)[0];
    size_t count = (size_t)((W_*)b)[1];
    W_ result = rex_cmm_mkbox(rex_tuple_new((int)count, values));
    free(values);
    free(builder);
    return result;
}
""",
    "rex_collections_vec_from": """
W_ rex_cmm_vec_begin(void)
{
    return rex_cmm_struct_begin();
}

void rex_cmm_vec_push(W_ builder, W_ value)
{
    rex_cmm_struct_push(builder, value);
}

W_ rex_cmm_vec_end(W_ builder)
{
    W_* b = (W_*)builder;
    RexValue* values = (RexValue*)((W_*)b)[0];
    size_t count = (size_t)((W_*)b)[1];
    W_ result = rex_cmm_mkbox(rex_collections_vec_from((int)count, values));
    free(values);
    free(builder);
    return result;
}
""",
    "rex_os_set_args": """
/* argv is captured by the generated Cmm entry point, which receives the
 * process arguments through the C main wrapper. */
void rex_cmm_os_set_args(int argc, char** argv)
{
    rex_os_set_args(argc, argv);
}
""",
    "rex_spawn": """
/* NOT SUPPORTED YET.
 *
 * `rex_spawn` takes a C function pointer and invokes it on a new OS thread.
 * gmm compiles Cmm functions to the GHC register convention (R1 = rax), not
 * the C ABI (first argument in rdi), so a Cmm label cannot be called back
 * from C.  A trampoline would also have to install a fresh `Sp`/`SpLim` on
 * the new thread, because `Sp` is a machine register and starts out
 * garbage there.  Until both are solved this fails loudly instead of
 * silently misbehaving. */
W_ rex_cmm_spawn(W_ fn, W_ ctx)
{
    (void)fn;
    (void)ctx;
    rex_panic("rex: the Cmm target does not support spawn yet");
    return NULL;
}
""",
}

# Extra runtime support that is not a thin wrapper.
EXTRA_BODIES = """
/* ---- runtime support ---- */

/* The Cmm backend needs a real machine stack: gmm's `return` writes through
 * Sp, and a standalone Cmm program starts with Sp pointing nowhere.  The
 * generated entry point calls this to obtain one, then sets
 * `Sp = base + size; SpLim = base;`. */
W_ rex_cmm_stack_alloc(unsigned long bytes)
{
    void* p = malloc(bytes);
    if (!p) {
        rex_panic("rex: could not allocate the Cmm stack");
    }
    return (W_)p;
}

/* Raw (unboxed) predicates.
 *
 * Every other wrapper returns a W_ box, but Cmm control flow wants a plain
 * machine integer it can test with `if (n != 0)`.  Foreign `int` returns do
 * work in gmm, so these expose the underlying C ints directly. */
int rex_cmm_truthy_raw(W_ v)
{
    return rex_is_truthy(rex_cmm_val(v));
}

int rex_cmm_tag_is_raw(W_ v, W_ tag)
{
    return rex_tag_is(rex_cmm_val(v), rex_cmm_cstr(tag)) ? 1 : 0;
}

int rex_cmm_result_is_raw(W_ v, W_ tag)
{
    return rex_result_is(rex_cmm_val(v), rex_cmm_cstr(tag)) ? 1 : 0;
}
"""

# Scalar parameter types that pass straight through the boundary.  These are
# spelled with C types so the generated shim is ordinary C; they line up with
# Cmm's `CInt` (int) and `W_` (StgWord) at the ABI level.
SCALARS = {
    "int": "int",
    "unsigned int": "unsigned int",
    "uint64_t": "uint64_t",
    "unsigned long": "unsigned long",
    "unsigned long long": "unsigned long long",
}

BOX = "W_"

HEADER_PROLOGUE = """\
/* GENERATED BY tools/gen_cmm_shim.py -- DO NOT EDIT BY HAND.
 *
 * Boxed FFI shims between the Cmm code generator and the Rex C runtime.
 *
 * gmm cannot receive a C `double` or a struct return value from a foreign
 * call, so every Rex value crosses the boundary as a `W_` pointer to a
 * heap-allocated `RexValue`.  These wrappers do that boxing in C, where the
 * real runtime signatures are available.
 */

#include "rex_rt.h"
#include "rex_cmm_shim.h"

#include <stdlib.h>
#include <string.h>

/* Allocate and populate one result box. */
W_ rex_cmm_mkbox(RexValue v)
{
    RexValue* p = (RexValue*)malloc(sizeof(RexValue));
    if (!p) {
        rex_panic("rex: out of memory allocating a value box");
    }
    *p = v;
    return (W_)p;
}

/* Borrow the value inside a box.  Null boxes behave like `nil`. */
RexValue rex_cmm_val(W_ p)
{
    if (!p) {
        return rex_nil();
    }
    return *(RexValue*)p;
}

/* Borrow the C string inside a box; null/ non-string boxes yield "". */
const char* rex_cmm_cstr(W_ p)
{
    RexValue v = rex_cmm_val(p);
    if (v.tag != REX_STR || !v.as.str) {
        return "";
    }
    return v.as.str;
}

/* Pass a data-section string through unchanged.
 *
 * A NUL-separated blob (struct field names) cannot travel as a boxed Rex
 * string: `rex_str` copies with strlen, so every field name after the first
 * would be truncated away.  This hands the raw pointer straight through. */
const char* rex_cmm_cstr_raw(W_ p)
{
    return (const char*)p;
}

/* Raw pointer payload accessor, for `&x` style references. */
void* rex_cmm_addr(W_ p)
{
    return (void*)p;
}
"""

# Prototypes for the hand-written section, emitted into both the .c prelude
# and the public header.
MANUAL_PROTOTYPES = [
    "W_ rex_cmm_num(double n);",
    "W_ rex_cmm_str_raw(W_ s);",
    "W_ rex_cmm_ptr(W_ p);",
    "W_ rex_cmm_ref(W_ addr);",
    "W_ rex_cmm_ref_mut(W_ addr);",
    "W_ rex_cmm_struct_begin(void);",
    "void rex_cmm_struct_push(W_ builder, W_ value);",
    "W_ rex_cmm_struct_end(W_ builder, W_ name, W_ field_names);",
    "W_ rex_cmm_struct_get(W_ obj, W_ field);",
    "void rex_cmm_struct_set(W_ obj, W_ field, W_ value);",
    "W_ rex_cmm_tuple_begin(void);",
    "W_ rex_cmm_tuple_end(W_ builder);",
    "W_ rex_cmm_vec_begin(void);",
    "void rex_cmm_vec_push(W_ builder, W_ value);",
    "W_ rex_cmm_vec_end(W_ builder);",
    "void rex_cmm_os_set_args(int argc, char** argv);",
    "W_ rex_cmm_spawn(W_ fn, W_ ctx);",
    "W_ rex_cmm_stack_alloc(unsigned long bytes);",
    "int rex_cmm_truthy_raw(W_ v);",
    "int rex_cmm_tag_is_raw(W_ v, W_ tag);",
    "int rex_cmm_result_is_raw(W_ v, W_ tag);",
]


def parse_functions(text):
    """Return [(name, ret, [(type, name), ...]), ...] for every prototype."""
    body = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    funcs = []
    for m in re.finditer(
        r"^\s*(RexValue|void|int|uint64_t|CInt)\s+(\w+)\s*\(([^;]*?)\)\s*;",
        body,
        flags=re.M | re.S,
    ):
        ret, name, params = m.group(1), m.group(2), m.group(3).strip()
        plist = []
        if params and params != "void":
            for raw in params.split(","):
                raw = raw.strip()
                pm = re.match(r"^(.*?)\b(\w+)$", raw, flags=re.S)
                if not pm:
                    plist.append((raw, None))
                    continue
                plist.append((" ".join(pm.group(1).split()), pm.group(2)))
        funcs.append((name, ret, plist))
    return funcs


def classify_param(ptype):
    if ptype == "RexValue":
        return "value"
    if ptype == "const char*":
        return "cstr"
    if ptype in SCALARS:
        return "scalar"
    return None


def emit_wrapper(name, ret, params):
    """Emit one rex_cmm_* wrapper, or None if the signature is unsupported."""
    kinds = []
    for ptype, _ in params:
        k = classify_param(ptype)
        if k is None:
            return None
        kinds.append(k)

    # `rex_add` -> wrapper `rex_cmm_add` forwarding to `rex_add`.
    base = name[len("rex_"):] if name.startswith("rex_") else name
    wrapper = "rex_cmm_" + base

    cargs = []
    for (ptype, pname), k in zip(params, kinds):
        if k == "value":
            cargs.append("rex_cmm_val(%s)" % pname)
        elif k == "cstr":
            cargs.append("rex_cmm_cstr(%s)" % pname)
        else:
            cargs.append(pname)

    call = "rex_%s(%s)" % (base, ", ".join(cargs))
    sig_params = ", ".join(
        "%s %s" % (BOX if k != "scalar" else SCALARS[ptype], pname)
        for (ptype, pname), k in zip(params, kinds)
    )

    if ret == "void":
        return "void %s(%s)\n{\n    %s;\n}\n" % (wrapper, sig_params, call)
    if ret == "RexValue":
        return "%s %s(%s)\n{\n    return rex_cmm_mkbox(%s);\n}\n" % (
            BOX,
            wrapper,
            sig_params,
            call,
        )
    if ret == "int":
        return "%s %s(%s)\n{\n    return rex_cmm_mkbox(rex_bool(%s));\n}\n" % (
            BOX,
            wrapper,
            sig_params,
            call,
        )
    if ret == "uint64_t":
        return "%s %s(%s)\n{\n    return rex_cmm_mkbox(rex_num((double)%s));\n}\n" % (
            BOX,
            wrapper,
            sig_params,
            call,
        )
    return None


def prototype(name, ret, params):
    """Render the public prototype for one generated wrapper."""
    base = name[len("rex_"):] if name.startswith("rex_") else name
    sig = ", ".join(
        "%s %s" % (BOX if classify_param(t) != "scalar" else SCALARS[t], pname)
        for t, pname in params
    )
    return "%s rex_cmm_%s(%s);" % (
        "void" if ret == "void" else BOX,
        base,
        sig,
    )


def main():
    with open(HEADER) as f:
        text = f.read()
    funcs = parse_functions(text)

    header_lines = [
        "/* GENERATED BY tools/gen_cmm_shim.py -- DO NOT EDIT BY HAND. */",
        "#ifndef REX_CMM_SHIM_H",
        "#define REX_CMM_SHIM_H",
        "",
        '#include "rex_rt.h"',
        "",
        "typedef void* W_;",
        "",
        "W_ rex_cmm_mkbox(RexValue v);",
        "RexValue rex_cmm_val(W_ p);",
        "const char* rex_cmm_cstr(W_ p);",
        "const char* rex_cmm_cstr_raw(W_ p);",
        "void* rex_cmm_addr(W_ p);",
        "",
    ]
    c_lines = [
        HEADER_PROLOGUE,
        "\n".join(MANUAL_PROTOTYPES),
        "\n/* ---- generated wrappers ---- */\n\n",
    ]

    skipped = []
    for name, ret, params in funcs:
        if name in MANUAL:
            skipped.append(name)
            continue
        w = emit_wrapper(name, ret, params)
        if w is None:
            skipped.append(name)
            continue
        c_lines.append(w)
        header_lines.append(prototype(name, ret, params))

    c_lines.append("\n/* ---- hand-written wrappers ---- */\n")
    for name in sorted(MANUAL_BODIES):
        c_lines.append(MANUAL_BODIES[name])
    c_lines.append(EXTRA_BODIES)

    header_lines.append("")
    header_lines.append("/* hand-written wrappers */")
    header_lines += MANUAL_PROTOTYPES
    header_lines += ["", "#endif /* REX_CMM_SHIM_H */", ""]

    with open(OUT_C, "w") as f:
        f.write("\n".join(c_lines))
    with open(OUT_H, "w") as f:
        f.write("\n".join(header_lines))

    # The Cmm code generator must know which runtime entry points return
    # nothing: Cmm requires every result to be read out of R1, so calling a
    # void shim as a value would be wrong.  Derive that from the real C
    # signatures rather than a hand-kept list, which silently drifted.
    void_fns = sorted(name for name, ret, _ in funcs if ret == "void")
    lua = [
        "-- GENERATED BY tools/gen_cmm_shim.py -- DO NOT EDIT BY HAND.",
        "--",
        "-- Runtime entry points whose C signature returns void.  A Cmm call to",
        "-- one of these must be emitted as a statement, not bound to a result.",
        "",
        "return {",
        "  void_fns = {",
    ]
    for name in void_fns:
        lua.append('    ["%s"] = true,' % name)
    lua.append("  },")
    lua.append("}")
    with open(OUT_LUA, "w") as f:
        f.write("\n".join(lua) + "\n")

    print("generated %d wrappers" % (len(funcs) - len(skipped)))
    print("wrote %s (%d void entry points)" % (os.path.relpath(OUT_LUA, ROOT), len(void_fns)))
    if skipped:
        print("manual (skipped): %s" % ", ".join(sorted(skipped)), file=sys.stderr)


if __name__ == "__main__":
    main()
