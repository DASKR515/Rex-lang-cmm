-- Cmm (C--) code generator for the Rex language.
--
-- This backend targets `gmm` (the GHC C-- manager) and links against the
-- same C runtime as the C backend, through the generated boxing shim in
-- `rex/runtime_c/rex_cmm_shim.c` (see `tools/gen_cmm_shim.py`).
--
-- Three gmm limitations shape the whole design.  All three were verified
-- experimentally against gmm v3.0 / GHC 9.10.3 on x86-64 Linux:
--
--   1. `return (v)` writes through the machine stack pointer, and a
--      standalone Cmm program starts with Sp pointing nowhere.  The
--      generated `main` therefore allocates a stack and sets
--      `Sp = base + size; SpLim = base;` before anything else.  With that
--      in place ordinary C-style returns work, so no continuation-passing
--      transformation (as in `cmm/ret.md`) is needed.
--
--   2. A C caller cannot invoke a Cmm function: gmm passes arguments in
--      the GHC registers (R1 = rax, R2 = rbx, ...) rather than the C ABI
--      (rdi, rsi, ...).  Shims are therefore strictly leaves -- they are
--      called *from* Cmm and never call back into it.  This is why `spawn`
--      is not supported by this target.
--
--   3. Foreign calls cannot return a C `double` or a struct.  Every Rex
--      value is consequently a `W_` pointer to a heap-allocated `RexValue`
--      box, and the shim layer does the boxing in C.  Foreign `int`,
--      `uint64_t` and pointer returns do work, which is what the control
--      flow predicates rely on.
--
-- Within Cmm: call a function with `call f(args);` and read the result
-- immediately from `R1` (then `R2`, `R3`, ... for multiple results), call C
-- with `(dest) = foreign "C" f(args);`, and lower every loop to `goto`
-- because Cmm has no `while` statement.

local Codegen = {}

-- Runtime entry point for each binary operator.
local BINARY_OPS = {
  ["+"] = "add",
  ["-"] = "sub",
  ["*"] = "mul",
  ["/"] = "div",
  ["%"] = "mod",
  ["=="] = "eq",
  ["!="] = "neq",
  ["<"] = "lt",
  ["<="] = "lte",
  [">"] = "gt",
  [">="] = "gte",
  ["&&"] = "and",
  ["||"] = "or",
}

-- Runtime functions that return nothing.  These must be emitted as bare
-- `foreign "C" f(...)` statements rather than result assignments.
-- Runtime entry points that return nothing, derived from the C signatures in
-- rex/runtime_c/rex_rt.h by tools/gen_cmm_shim.py.  A Cmm call to one of these
-- has to be emitted as a statement because there is no result to read.
local SHIM_TABLE = require("compiler.codegen.cmm_shim_table")
local RUNTIME_BUILTINS = require("compiler.codegen.runtime_builtins")
local VOID_BUILTINS = SHIM_TABLE.void_fns

-- Default size of the Cmm machine stack, in bytes.  gmm inserts no stack
-- checks of its own, so this is the only bound on Rex recursion depth.
local DEFAULT_STACK_BYTES = 64 * 1024 * 1024

-- Runtime entry-point tables, shared with the C backend so both targets
-- accept the same programs and name the same C symbols.  Each value becomes a
-- `rex_cmm_<name>` shim call.
local BUILTINS = RUNTIME_BUILTINS.builtins

-- Lowerings the C backend emits directly rather than through its table, so the
-- Cmm backend has to resolve them by name.
for _, name in ipairs({ "is_truthy", "panic", "tag_is", "result_is" }) do
  BUILTINS[name] = "rex_" .. name
end

-- Per-module builtins, keyed by the last segment of the `use rex::<mod>` path.
local MODULE_BUILTINS = RUNTIME_BUILTINS.module_builtins

-- Encode a string as a Cmm `bits8[]` literal.  Every byte is written as
-- \xNN because GHC's lexer reads \x as a *greedy* hex escape: a literal like
-- "\x41BC" would swallow the "BC" as more hex digits.  Emitting every byte
-- keeps adjacent escapes unambiguous, and the trailing \00 supplies the NUL
-- that the C string functions in the runtime expect.
local function cmm_string_literal(text)
  local out = {}
  for i = 1, #text do
    out[#out + 1] = string.format("\\x%02X", text:byte(i))
  end
  -- Hex escapes in Cmm are greedy (they consume every following hex digit),
  -- so each byte must be written as its own escape, including the NUL
  -- terminator.
  out[#out + 1] = "\\x00"
  return '"' .. table.concat(out) .. '"'
end

function Codegen.generate(ast, opts)
  opts = opts or {}
  local stack_bytes = opts.cmm_stack_bytes or DEFAULT_STACK_BYTES

  local ctx = {
    out = {},        -- finished top-level Cmm text
    body = {},       -- lines of the function currently being emitted
    indent = 1,
    tmp = 0,
    label = 0,
    decls = {},      -- declarations for the function being emitted
    string_labels = {},
    string_order = {},
    scopes = { {} }, -- Rex name -> Cmm local
    types = { {} },   -- Rex name -> type annotation (method/field resolution)
    functions = {},  -- Rex name -> Cmm function name
    structs = {},
    enums = {},
    methods = {},
    imports = {},
    external_modules = opts.external_modules or {},
    loops = {},      -- stack of { break_label, continue_label }
    defers = {},     -- `defer` statements pending for the current block
  }

  ---------------------------------------------------------------------------
  -- emission primitives

  local function emit(text)
    ctx.body[#ctx.body + 1] = string.rep("    ", ctx.indent) .. text
  end

  local function next_label(stem)
    ctx.label = ctx.label + 1
    return string.format("rxr_%s%d", stem, ctx.label)
  end

  local function next_tmp(stem)
    ctx.tmp = ctx.tmp + 1
    return string.format("rxr_%s%d", stem or "v", ctx.tmp)
  end

  local function declare(name, ctype)
    ctx.decls[#ctx.decls + 1] = { name = name, ctype = ctype or "W_" }
    return name
  end

  local function new_local(stem)
    return declare(next_tmp(stem or "v"), "W_")
  end

  -- A D_ local is needed whenever a numeric literal must cross the FFI
  -- boundary as a real C double (gmm passes double *arguments* fine; only
  -- double *returns* are broken).
  local function new_double_local()
    return declare(next_tmp("d"), "D_")
  end

  ---------------------------------------------------------------------------
  -- string literals

  local function string_label(text)
    local existing = ctx.string_labels[text]
    if existing then
      return existing
    end
    local lbl = string.format("rxr_s%d", #ctx.string_order + 1)
    ctx.string_labels[text] = lbl
    ctx.string_order[#ctx.string_order + 1] = { text = text, label = lbl }
    return lbl
  end

  -- A boxed Rex string for `text`, as a Cmm local.
  --
  -- The data label is cached because labels are file-global and always
  -- available.  The *box* deliberately is not cached: a cached box would be
  -- assigned only at its first use site, so an arm that used the same literal
  -- could read it on a path that never passed through the first use.  gmm's
  -- register allocator rejects that as an uninitialized read.
  local function string_value(text)
    local lbl = string_label(text)
    local tmp = new_local("str")
    emit(string.format('(%s) = foreign "C" rex_cmm_str_raw(%s "ptr");', tmp, lbl))
    return tmp
  end

  ---------------------------------------------------------------------------
  -- scopes

  local function scope_lookup(name)
    for i = #ctx.scopes, 1, -1 do
      local hit = ctx.scopes[i][name]
      if hit then
        return hit
      end
    end
    return nil
  end

  local function bind(name, local_name)
    ctx.scopes[#ctx.scopes][name] = local_name
  end

  -- Declared/inferred type of a binding, used only to resolve method calls
  -- and field types.  Mirrors the C backend's annotations: "struct:Name",
  -- "enum:Name", "num", "str", "bool", or "unknown".
  local function bind_type(name, type_name)
    ctx.types[#ctx.types][name] = type_name or "unknown"
  end

  local function type_lookup(name)
    for i = #ctx.types, 1, -1 do
      local hit = ctx.types[i][name]
      if hit then
        return hit
      end
    end
    return nil
  end

  local function push_scope()
    ctx.scopes[#ctx.scopes + 1] = {}
    ctx.types[#ctx.types + 1] = {}
  end

  local function pop_scope()
    table.remove(ctx.scopes)
    table.remove(ctx.types)
  end

  ---------------------------------------------------------------------------
  -- foreign calls

  -- `rex_foo` -> `rex_cmm_foo`.
  local function shim(runtime_name)
    if type(runtime_name) ~= "string" or runtime_name:sub(1, 4) ~= "rex_" then
      error("not a runtime function: " .. tostring(runtime_name))
    end
    return "rex_cmm_" .. runtime_name:sub(5)
  end

  local function foreign_args(args)
    local list = args or {}
    if #list == 0 then
      -- gmm requires an explicit argument list, even when empty.
      return "()"
    end
    return "(" .. table.concat(list, ", ") .. ")"
  end

  local function call_void(runtime_name, args)
    emit(string.format('foreign "C" %s%s;', shim(runtime_name), foreign_args(args)))
  end

  local function call_boxed(runtime_name, args)
    local tmp = new_local("r")
    emit(string.format('(%s) = foreign "C" %s%s;', tmp, shim(runtime_name), foreign_args(args)))
    return tmp
  end

  -- Builder entry points live in the shim but are not runtime functions, so
  -- they bypass the `rex_` -> `rex_cmm_` rewrite.
  local function call_raw(c_name, args)
    local tmp = new_local("r")
    emit(string.format('(%s) = foreign "C" %s%s;', tmp, c_name, foreign_args(args)))
    return tmp
  end

  local function call_raw_void(c_name, args)
    emit(string.format('foreign "C" %s%s;', c_name, foreign_args(args)))
  end

  local function nil_value()
    return call_boxed("rex_nil", {})
  end

  local function bool_value(flag)
    return call_boxed("rex_bool", { flag and "1" or "0" })
  end

  -- A fresh boxed 1, used as the loop increment.
  --
  -- This deliberately is not cached across uses.  A cached local would be
  -- assigned only at its first use site, so any path reaching a later use
  -- without passing through the first one would read an uninitialized Cmm
  -- register, which gmm's register allocator rejects.
  local function one_value()
    local d = new_double_local()
    emit(string.format("%s = 1.0;", d))
    return call_boxed("rex_num", { d })
  end

  ---------------------------------------------------------------------------
  -- user function calls

  -- Call a generated Cmm function and capture its result from R1.  R1 must
  -- be read before any other code can clobber it.
  local function call_cmm(fn_name, args)
    local tmp = new_local("r")
    emit(string.format("call %s%s;", fn_name, foreign_args(args)))
    emit(string.format("%s = R1;", tmp))
    return tmp
  end

  ---------------------------------------------------------------------------
  -- forward declarations

  local emit_expr
  local emit_block

  ---------------------------------------------------------------------------
  -- conditions

  -- A plain C `int` usable directly in a Cmm `if`.
  local function truthy(value)
    local flag = new_local("c")
    emit(string.format('(%s) = foreign "C" rex_cmm_truthy_raw(%s);', flag, value))
    return flag
  end

  local function condition(expr)
    return truthy(emit_expr(expr))
  end

  local function tag_test(value, tag)
    local flag = new_local("t")
    emit(
      string.format(
        '(%s) = foreign "C" rex_cmm_tag_is_raw(%s, %s);',
        flag,
        value,
        string_value(tag)
      )
    )
    return flag
  end

  ---------------------------------------------------------------------------
  -- composite literals

  -- The struct field-name table as a raw data-section pointer.  It has to stay
  -- a NUL-separated blob: boxing it would copy it with strlen and drop every
  -- name after the first.
  local function field_name_blob(def)
    local parts = {}
    for _, field in ipairs(def.fields) do
      parts[#parts + 1] = field.name .. "\0"
    end
    return string_label(table.concat(parts)) .. ' "ptr"'
  end

  local function build_struct(name, def, values)
    local builder = call_raw("rex_cmm_struct_begin", {})
    for i, field in ipairs(def.fields) do
      local v = values[i]
      if v then
        call_raw_void("rex_cmm_struct_push", { builder, v })
      else
        call_raw_void("rex_cmm_struct_push", { builder, nil_value() })
      end
    end
    return call_raw("rex_cmm_struct_end", { builder, string_value(name), field_name_blob(def) })
  end

  local function find_enum_variant(enum_name, variant)
    local def = ctx.enums[enum_name]
    if not def then
      return nil
    end
    for _, v in ipairs(def.variants or {}) do
      if v.name == variant then
        return v
      end
    end
    return nil
  end

  local function enum_tag_literal(variant, payload)
    return call_boxed("rex_tag", { string_value(variant), payload or nil_value() })
  end

  ---------------------------------------------------------------------------
  -- unsupported constructs

  local UNSUPPORTED = {
    Spawn = "spawn",
    Bond = "explicit bonds",
    Commit = "bond commit",
    Rollback = "bond rollback",
    WithinBlock = "within blocks",
    DuringBlock = "during blocks",
    DebugOwnership = "ownership debug directives",
  }

  local function unsupported(node, what)
    error(
      string.format(
        "the Cmm target does not support %s yet (node kind %s)",
        what or node.kind,
        tostring(node.kind)
      )
    )
  end

  ---------------------------------------------------------------------------
  -- call resolution

  local function builtin_result(runtime_name)
    if VOID_BUILTINS[runtime_name] then
      return { kind = "void", name = runtime_name }
    end
    if runtime_name == "rex_collections_vec_from" then
      return { kind = "vec_from" }
    end
    return { kind = "shim", name = runtime_name }
  end

  -- Defined in the statements section below, once the type tables exist.
  local receiver_named_type

  -- Decide what a call target refers to.
  local function resolve_callee(callee)
    if callee.kind == "Generic" then
      callee = callee.expr
    end

    if callee.kind == "Identifier" then
      local name = callee.name
      local fn = ctx.functions[name]
      if fn then
        return { kind = "cmm", name = fn, receiver = false }
      end
      local builtin = BUILTINS[name]
      if builtin then
        return builtin_result(builtin)
      end
      error("call to unknown function: " .. tostring(name))
    end

    if callee.kind == "Member" then
      local obj = callee.object
      local prop = callee.property
      if obj.kind == "Identifier" then
        local module = ctx.imports[obj.name]
        if module then
          local table_ = MODULE_BUILTINS[module]
          local target = table_ and table_[prop]
          if target then
            return builtin_result(target)
          end
          local export = ctx.external_modules[module] and ctx.external_modules[module][prop]
          if export then
            local fn = ctx.functions[export.internal_name] or export.internal_name
            return { kind = "cmm", name = fn, receiver = false }
          end
          return builtin_result("rex_" .. module .. "_" .. prop)
        end
        if prop == "new" and ctx.structs[obj.name] then
          return { kind = "struct_new", name = obj.name }
        end
        if ctx.enums[obj.name] then
          return { kind = "enum_variant", enum = obj.name, variant = prop }
        end
        -- Method on a value whose name is also a struct or enum type.
        local methods = ctx.methods[obj.name]
        if methods and methods[prop] then
          return { kind = "cmm", name = methods[prop], receiver = true }
        end
      end
      if callee.property == "send" then
        return { kind = "shim", name = "rex_sender_send", receiver = true }
      end
      if callee.property == "recv" then
        return { kind = "shim", name = "rex_receiver_recv", receiver = true }
      end
      -- Otherwise the receiver is a value: resolve its struct/enum type from
      -- the binding's recorded annotation and look the method up there.
      local named = receiver_named_type(obj)
      local owner = named and named:match("^struct:(.+)$") or named and named:match("^enum:(.+)$")
      if owner then
        local methods = ctx.methods[owner]
        if methods and methods[prop] then
          return { kind = "cmm", name = methods[prop], receiver = true }
        end
      end
    end

    error(
      "the Cmm target cannot resolve this call target (method calls need a "
        .. "resolvable receiver type): "
        .. (callee.kind == "Member" and tostring(callee.property) or tostring(callee.kind))
    )
  end

  ---------------------------------------------------------------------------
  -- calls

  local function emit_call(expr)
    local callee = expr.callee
    if callee.kind == "Generic" then
      callee = callee.expr
    end
    local target = resolve_callee(callee)

    if target.kind == "struct_new" then
      local def = ctx.structs[target.name]
      local values = {}
      for _, a in ipairs(expr.args or {}) do
        values[#values + 1] = emit_expr(a)
      end
      return build_struct(target.name, def, values)
    end

    if target.kind == "enum_variant" then
      local args = {}
      for _, a in ipairs(expr.args or {}) do
        args[#args + 1] = emit_expr(a)
      end
      local variant = find_enum_variant(target.enum, target.variant)
      if not variant then
        error("unknown enum variant: " .. target.enum .. "." .. target.variant)
      end
      local expected = variant.types and #variant.types or 0
      if expected ~= #args then
        error(
          string.format(
            "enum variant %s.%s expects %d value(s), got %d",
            target.enum,
            target.variant,
            expected,
            #args
          )
        )
      end
      return enum_tag_literal(target.variant, args[1])
    end

    -- `col.vec_from(a, b, c)` is variadic in Rex, but the shim entry point
    -- takes a `RexValue*` that Cmm cannot build.  Reuse the same
    -- accumulate-then-finish builder the array-literal path uses.
    if target.kind == "vec_from" then
      local builder = call_raw("rex_cmm_vec_begin", {})
      for _, a in ipairs(expr.args or {}) do
        call_raw_void("rex_cmm_vec_push", { builder, emit_expr(a) })
      end
      return call_raw("rex_cmm_vec_end", { builder })
    end

    local args = {}
    if target.receiver and callee.kind == "Member" then
      args[#args + 1] = emit_expr(callee.object)
    end
    for _, a in ipairs(expr.args or {}) do
      args[#args + 1] = emit_expr(a)
    end

    if target.kind == "cmm" then
      return call_cmm(target.name, args)
    end
    if target.kind == "void" then
      call_void(target.name, args)
      return nil_value()
    end
    return call_boxed(target.name, args)
  end

  ---------------------------------------------------------------------------
  -- expressions

  local function emit_number_literal(text)
    -- Cmm needs a float literal for a D_ target, so give bare integers a
    -- fractional part rather than relying on implicit widening.
    local value = tostring(text)
    if not value:find("[%.eE]") then
      value = value .. ".0"
    end
    local d = new_double_local()
    emit(string.format("%s = %s;", d, value))
    return call_boxed("rex_num", { d })
  end

  local function emit_struct_literal(expr)
    local def = ctx.structs[expr.name]
    if not def then
      error("unknown struct in literal: " .. tostring(expr.name))
    end
    local by_name = {}
    for _, f in ipairs(expr.fields or {}) do
      by_name[f.name] = f.value
    end
    -- Field order comes from the declaration, not the literal.
    local values = {}
    for _, field in ipairs(def.fields) do
      local node = by_name[field.name]
      if node then
        values[#values + 1] = emit_expr(node)
      end
    end
    return build_struct(expr.name, def, values)
  end

  -- The `?` propagate operator: evaluate, return early from the enclosing
  -- function when the value is an Err, otherwise unwrap it.  Ordinary Cmm
  -- returns make this a direct control-flow construct.
  local function emit_try(expr)
    local inner = emit_expr(expr.expr)
    local is_err = truthy(call_boxed("rex_result_is", { inner, string_value("Err") }))
    emit(string.format("if (%s != 0) { return (%s); }", is_err, inner))
    -- Anything that reaches here is an Ok, so the unwrap is unconditional and
    -- the destination is always assigned on this path.
    return call_boxed("rex_result_value", { inner })
  end

  emit_expr = function(expr)
    local kind = expr.kind
    if kind == "Try" then
      return emit_try(expr)
    elseif kind == "Nil" then
      return nil_value()
    elseif kind == "Bool" then
      return bool_value(expr.value)
    elseif kind == "Number" then
      return emit_number_literal(expr.value)
    elseif kind == "String" then
      return string_value(expr.value)
    elseif kind == "Identifier" then
      local local_name = scope_lookup(expr.name)
      if local_name then
        return local_name
      end
      local fn = ctx.functions[expr.name]
      if fn then
        return call_cmm(fn, {})
      end
      error("unknown identifier: " .. tostring(expr.name))
    elseif kind == "Generic" then
      return emit_expr(expr.expr)
    elseif kind == "Unary" then
      local v = emit_expr(expr.expr)
      if expr.op == "-" then
        return call_boxed("rex_neg", { v })
      elseif expr.op == "!" then
        return call_boxed("rex_not", { v })
      end
      error("unsupported unary operator: " .. tostring(expr.op))
    elseif kind == "Binary" then
      local op = BINARY_OPS[expr.op]
      if not op then
        error("unsupported binary operator: " .. tostring(expr.op))
      end
      local l = emit_expr(expr.left)
      local r = emit_expr(expr.right)
      return call_boxed("rex_" .. op, { l, r })
    elseif kind == "Call" then
      return emit_call(expr)
    elseif kind == "Member" then
      if expr.object.kind == "Identifier" and ctx.enums[expr.object.name] then
        local variant = find_enum_variant(expr.object.name, expr.property)
        if variant then
          local expected = variant.types and #variant.types or 0
          if expected > 0 then
            error(
              "enum variant " .. expr.object.name .. "." .. expr.property .. " requires a payload"
            )
          end
          return enum_tag_literal(expr.property)
        end
      end
      local obj = emit_expr(expr.object)
      return call_boxed("rex_struct_get", { obj, string_value(expr.property) })
    elseif kind == "Index" then
      local obj = emit_expr(expr.object)
      local idx = emit_expr(expr.index)
      return call_boxed("rex_collections_get", { obj, idx })
    elseif kind == "Slice" then
      local obj = emit_expr(expr.object)
      local start = emit_expr(expr.start)
      local finish = expr.finish and emit_expr(expr.finish) or nil_value()
      return call_boxed("rex_collections_slice", { obj, start, finish })
    elseif kind == "Try" then
      return call_boxed("rex_try", { emit_expr(expr.expr) })
    elseif kind == "Deref" then
      return call_boxed("rex_deref", { emit_expr(expr.expr) })
    elseif kind == "Borrow" then
      local target = expr.expr
      if target.kind ~= "Identifier" then
        error("borrow expects an identifier")
      end
      local local_name = scope_lookup(target.name)
      if not local_name then
        error("borrow of unknown identifier: " .. tostring(target.name))
      end
      -- The box pointer *is* the address the runtime wants.
      if expr.mutable then
        return call_boxed("rex_ref_mut", { local_name })
      end
      return call_boxed("rex_ref", { local_name })
    elseif kind == "Array" then
      local elems = {}
      for _, e in ipairs(expr.elements or {}) do
        elems[#elems + 1] = emit_expr(e)
      end
      if #elems == 0 then
        return call_boxed("rex_collections_vec_new", {})
      end
      local builder = call_raw("rex_cmm_vec_begin", {})
      for _, e in ipairs(elems) do
        call_raw_void("rex_cmm_vec_push", { builder, e })
      end
      return call_raw("rex_cmm_vec_end", { builder })
    elseif kind == "StructLit" then
      return emit_struct_literal(expr)
    end
    unsupported(expr)
  end

  ---------------------------------------------------------------------------
  -- statements

  -- Does this statement list end by transferring control away?
  local function block_terminates(block)
    if not block or not block.statements then
      return false
    end
    local last = block.statements[#block.statements]
    if not last then
      return false
    end
    return last.kind == "Return" or last.kind == "Break" or last.kind == "Continue"
  end

  local function block_tail_expr(block)
    if not block or not block.statements then
      return nil
    end
    local last = block.statements[#block.statements]
    if last and last.kind == "ExprStmt" then
      return last.expr
    end
    return nil
  end

  local NUMERIC_TYPES = {
    num = true, f32 = true, f64 = true,
    i8 = true, i16 = true, i32 = true, i64 = true,
    u8 = true, u16 = true, u32 = true, u64 = true,
  }

  local function type_base(t)
    if type(t) ~= "string" then
      return nil
    end
    -- Strip generic arguments and any reference/ownership markers.
    local base = t:match("^([^<]*)") or t
    base = base:gsub("^%s+", ""):gsub("%s+$", "")
    base = base:gsub("^[&*]+", "")
    return base
  end

  -- The struct a `Type.new(...)` / `Type{...}` expression constructs, if any.
  local function constructed_struct_name(expr)
    if not expr then
      return nil
    end
    if expr.kind == "StructLit" and ctx.structs[expr.name] then
      return expr.name
    end
    if expr.kind == "Call" then
      local callee = expr.callee
      if callee.kind == "Generic" then
        callee = callee.expr
      end
      if callee.kind == "Member" and callee.property == "new" then
        if callee.object.kind == "Identifier" and ctx.structs[callee.object.name] then
          return callee.object.name
        end
        local module = ctx.imports[callee.object.kind == "Identifier" and callee.object.name or ""]
        local export = module and ctx.external_modules[module] and ctx.external_modules[module][callee.object.property]
        local kind = export and (export.kind or (export.item and export.item.kind))
        if kind == "Struct" then
          return export.internal_name or (export.item and export.item.name) or callee.object.property
        end
      end
    end
    return nil
  end

  -- The enum an `Enum.Variant` expression names, if any.
  local function constructed_enum_name(expr)
    if not expr then
      return nil
    end
    if expr.kind == "Call" then
      -- `Option.Some(7)`: a variant constructor applied to its payload.
      local callee = expr.callee
      if callee.kind == "Generic" then
        callee = callee.expr
      end
      if callee.kind == "Member" and callee.object.kind == "Identifier" and ctx.enums[callee.object.name] then
        return callee.object.name
      end
      return nil
    end
    if expr.kind ~= "Member" then
      return nil
    end
    if expr.object.kind == "Identifier" and ctx.enums[expr.object.name] then
      return expr.object.name
    end
    if expr.object.kind == "Member" and expr.object.object.kind == "Identifier" then
      local module = ctx.imports[expr.object.object.name]
      local export = module and ctx.external_modules[module] and ctx.external_modules[module][expr.object.property]
      local kind = export and (export.kind or (export.item and export.item.kind))
      if kind == "Enum" then
        return export.internal_name or (export.item and export.item.name) or expr.object.property
      end
    end
    return nil
  end

  -- The struct or enum a receiver expression has, so `p.len()` can be resolved
  -- without a full type checker.
  receiver_named_type = function(expr)
    if not expr then
      return nil
    end
    if expr.kind == "Identifier" then
      return type_lookup(expr.name)
    end
    if expr.kind == "Generic" then
      return receiver_named_type(expr.expr)
    end
    if expr.kind == "Member" then
      -- `a.b.c()`: walk to the field's declared type.
      local parent = receiver_named_type(expr.object)
      local struct_name = parent and parent:match("^struct:(.+)$")
      if not struct_name then
        return nil
      end
      local def = ctx.structs[struct_name]
      if not def then
        return nil
      end
      for _, field in ipairs(def.fields or {}) do
        if field.name == expr.property then
          local base = type_base(field.type)
          if base and ctx.structs[base] then
            return "struct:" .. base
          end
          if base and ctx.enums[base] then
            return "enum:" .. base
          end
          return nil
        end
      end
    end
    return nil
  end

  -- The type annotation to record for a `let` binding.
  local function binding_type(stmt)
    local base = type_base(stmt.type)
    if base then
      if NUMERIC_TYPES[base] then
        return "num"
      elseif base == "bool" then
        return "bool"
      elseif base == "str" or base == "string" then
        return "str"
      elseif ctx.structs[base] then
        return "struct:" .. base
      elseif ctx.enums[base] then
        return "enum:" .. base
      end
    end
    local s = constructed_struct_name(stmt.value)
    if s then
      return "struct:" .. s
    end
    local e = constructed_enum_name(stmt.value)
    if e then
      return "enum:" .. e
    end
    if stmt.value and stmt.value.kind == "Try" then
      return binding_type({ type = nil, value = stmt.value.expr })
    end
    return "unknown"
  end

  local function emit_let(stmt)
    local value = emit_expr(stmt.value)
    local pattern = stmt.pattern
    if pattern.kind == "IdentPattern" then
      bind(pattern.name, value)
      bind_type(pattern.name, binding_type(stmt))
      return
    end
    if pattern.kind == "TuplePattern" then
      -- Destructuring reads fields positionally via the tuple accessor.
      for i, name in ipairs(pattern.names or {}) do
        local element = call_boxed("rex_tuple_get", { value, tostring(i - 1) })
        bind(name, element)
      end
      return
    end
    error("unsupported let pattern: " .. tostring(pattern.kind))
  end

  local function emit_if(stmt)
    local flag = condition(stmt.cond)
    emit(string.format("if (%s != 0) {", flag))
    ctx.indent = ctx.indent + 1
    push_scope()
    emit_block(stmt.then_block)
    pop_scope()
    ctx.indent = ctx.indent - 1
    if stmt.else_block then
      emit("} else {")
      ctx.indent = ctx.indent + 1
      push_scope()
      emit_block(stmt.else_block)
      pop_scope()
      ctx.indent = ctx.indent - 1
    end
    emit("}")
  end

  -- `if` in value position: both arms bind to one local.
  local function emit_if_value(stmt, dest)
    local flag = condition(stmt.cond)
    local else_label = next_label("ifelse")
    local end_label = next_label("ifend")
    emit(string.format("if (%s == 0) { goto %s; }", flag, else_label))
    local then_tail = block_tail_expr(stmt.then_block)
    if then_tail then
      emit(string.format("%s = %s;", dest, emit_expr(then_tail)))
    else
      emit_block(stmt.then_block)
      emit(string.format("%s = %s;", dest, nil_value()))
    end
    emit(string.format("goto %s;", end_label))
    emit(string.format("%s:", else_label))
    if stmt.else_block then
      local else_tail = block_tail_expr(stmt.else_block)
      if else_tail then
        emit(string.format("%s = %s;", dest, emit_expr(else_tail)))
      else
        emit_block(stmt.else_block)
        emit(string.format("%s = %s;", dest, nil_value()))
      end
    else
      emit(string.format("%s = %s;", dest, nil_value()))
    end
    emit(string.format("%s:", end_label))
  end

  -- Cmm has no `while`, so loops are lowered to `goto`.  A single label sits
  -- at the test: it is both the first thing executed and the `continue`
  -- target, so the condition is re-evaluated on every pass.
  local function emit_while(stmt)
    local top = next_label("wtop")
    local done = next_label("wdone")
    emit(string.format("%s:", top))
    local flag = condition(stmt.cond)
    emit(string.format("if (%s == 0) { goto %s; }", flag, done))
    ctx.loops[#ctx.loops + 1] = { break_label = done, continue_label = top }
    push_scope()
    emit_block(stmt.body)
    pop_scope()
    table.remove(ctx.loops)
    emit(string.format("goto %s;", top))
    emit(string.format("%s:", done))
  end

  -- `for name in start..finish`
  local function emit_for_range(stmt)
    local idx = new_local("i")
    local start = emit_expr(stmt.range_start)
    local finish = emit_expr(stmt.range_end)
    emit(string.format("%s = %s;", idx, start))
    local top = next_label("ftop")
    local step = next_label("fstep")
    local done = next_label("fdone")
    emit(string.format("%s:", top))
    -- Half-open range, tested through the runtime so boxed values compare.
    local past_end = call_boxed("rex_gte", { idx, finish })
    local flag = truthy(past_end)
    emit(string.format("if (%s != 0) { goto %s; }", flag, done))
    -- `continue` targets the step, not the test: a `for` loop's increment runs
    -- on every pass, including the one a `continue` jumps into.
    ctx.loops[#ctx.loops + 1] = { break_label = done, continue_label = step }
    push_scope()
    bind(stmt.name, idx)
    emit_block(stmt.body)
    pop_scope()
    table.remove(ctx.loops)
    emit(string.format("%s:", step))
    local bumped = call_boxed("rex_add", { idx, one_value() })
    emit(string.format("%s = %s;", idx, bumped))
    emit(string.format("goto %s;", top))
    emit(string.format("%s:", done))
  end

  -- `for name in collection`
  local function emit_for_iter(stmt)
    local seq = emit_expr(stmt.iter)
    local len = call_boxed("rex_collections_vec_len", { seq })
    local idx = new_local("i")
    local top = next_label("itop")
    local step = next_label("itstep")
    local done = next_label("itdone")
    local zero = new_double_local()
    emit(string.format("%s = 0.0;", zero))
    emit(string.format("%s = %s;", idx, call_boxed("rex_num", { zero })))
    emit(string.format("%s:", top))
    local past_end = call_boxed("rex_gte", { idx, len })
    local flag = truthy(past_end)
    emit(string.format("if (%s != 0) { goto %s; }", flag, done))
    ctx.loops[#ctx.loops + 1] = { break_label = done, continue_label = step }
    push_scope()
    bind(stmt.name, call_boxed("rex_collections_vec_get", { seq, idx }))
    emit_block(stmt.body)
    pop_scope()
    table.remove(ctx.loops)
    emit(string.format("%s:", step))
    local bumped = call_boxed("rex_add", { idx, one_value() })
    emit(string.format("%s = %s;", idx, bumped))
    emit(string.format("goto %s;", top))
    emit(string.format("%s:", done))
  end

  local function emit_for(stmt)
    if stmt.iter then
      emit_for_iter(stmt)
    else
      emit_for_range(stmt)
    end
  end

  -- `match` in value position.  Cmm has no `||`, so multi-tag arms test
  -- their tags sequentially and jump to the arm body on the first hit.
  local function emit_match_value(stmt, dest)
    local subject = emit_expr(stmt.expr)
    local arms = stmt.arms or {}
    local end_label = next_label("mend")
    local has_wildcard = false
    for _, arm in ipairs(arms) do
      if arm.wildcard then
        has_wildcard = true
      end
    end

    -- Test chain: each arm's tests fall through to the next arm.
    for i, arm in ipairs(arms) do
      local body_label = next_label("mbody")
      if arm.wildcard then
        emit(string.format("goto %s;", body_label))
      else
        local tags = arm.tags or { arm.tag }
        for _, t in ipairs(tags) do
          local test = tag_test(subject, t)
          emit(string.format("if (%s != 0) { goto %s; }", test, body_label))
        end
      end
      if i == #arms and not has_wildcard then
        -- Unreachable fallthrough when nothing matched.
        emit(string.format("goto %s;", end_label))
      end
      -- The body is emitted after all tests so the fallthrough chain stays
      -- contiguous; jump past it here.
      local skip = next_label("mnext")
      emit(string.format("goto %s;", skip))
      emit(string.format("%s:", body_label))
      local tail = block_tail_expr(arm.body)
      if tail then
        push_scope()
        if arm.binding then
          bind(arm.binding, call_boxed("rex_tag_value", { subject }))
        end
        emit(string.format("%s = %s;", dest, emit_expr(tail)))
        pop_scope()
      else
        push_scope()
        if arm.binding then
          bind(arm.binding, call_boxed("rex_tag_value", { subject }))
        end
        emit_block(arm.body)
        pop_scope()
        emit(string.format("%s = %s;", dest, nil_value()))
      end
      if not block_terminates(arm.body) then
        emit(string.format("goto %s;", end_label))
      end
      emit(string.format("%s:", skip))
    end
    emit(string.format("%s:", end_label))
  end

  -- `match` in statement position.
  local function emit_match(stmt)
    local subject = emit_expr(stmt.expr)
    local arms = stmt.arms or {}
    local end_label = next_label("mend")
    local has_wildcard = false
    for _, arm in ipairs(arms) do
      if arm.wildcard then
        has_wildcard = true
      end
    end

    for i, arm in ipairs(arms) do
      local body_label = next_label("mbody")
      if arm.wildcard then
        emit(string.format("goto %s;", body_label))
      else
        local tags = arm.tags or { arm.tag }
        for _, t in ipairs(tags) do
          local test = tag_test(subject, t)
          emit(string.format("if (%s != 0) { goto %s; }", test, body_label))
        end
      end
      if i == #arms and not has_wildcard then
        emit(string.format("goto %s;", end_label))
      end
      local skip = next_label("mnext")
      emit(string.format("goto %s;", skip))
      emit(string.format("%s:", body_label))
      push_scope()
      if arm.binding then
        bind(arm.binding, call_boxed("rex_tag_value", { subject }))
      end
      emit_block(arm.body)
      pop_scope()
      if not block_terminates(arm.body) then
        emit(string.format("goto %s;", end_label))
      end
      emit(string.format("%s:", skip))
    end
    emit(string.format("%s:", end_label))
  end

  local function emit_stmt(stmt)
    local kind = stmt.kind
    if kind == "ExprStmt" then
      emit_expr(stmt.expr)
    elseif kind == "Let" then
      emit_let(stmt)
    elseif kind == "Return" then
      if stmt.value then
        emit(string.format("return (%s);", emit_expr(stmt.value)))
      else
        emit(string.format("return (%s);", nil_value()))
      end
    elseif kind == "If" then
      emit_if(stmt)
    elseif kind == "While" then
      emit_while(stmt)
    elseif kind == "For" then
      emit_for(stmt)
    elseif kind == "Break" then
      local frame = ctx.loops[#ctx.loops]
      if not frame then
        error("break outside of a loop")
      end
      emit(string.format("goto %s;", frame.break_label))
    elseif kind == "Continue" then
      local frame = ctx.loops[#ctx.loops]
      if not frame then
        error("continue outside of a loop")
      end
      emit(string.format("goto %s;", frame.continue_label))
    elseif kind == "Match" then
      emit_match(stmt)
    elseif kind == "Block" then
      emit_block(stmt)
    elseif kind == "Unsafe" then
      emit_block(stmt.block)
    elseif kind == "Assign" then
      local value = emit_expr(stmt.value)
      local target = scope_lookup(stmt.name)
      if not target then
        error("assignment to unknown identifier: " .. tostring(stmt.name))
      end
      emit(string.format("%s = %s;", target, value))
    elseif kind == "MemberAssign" then
      local obj = emit_expr(stmt.object)
      local value = emit_expr(stmt.value)
      call_void("rex_struct_set", { obj, string_value(stmt.property), value })
    elseif kind == "IndexAssign" then
      local obj = emit_expr(stmt.object)
      local index = emit_expr(stmt.index)
      local value = emit_expr(stmt.value)
      call_void("rex_collections_set", { obj, index, value })
    elseif kind == "DerefAssign" then
      local target = scope_lookup(stmt.name)
      if not target then
        error("deref assignment to unknown identifier: " .. tostring(stmt.name))
      end
      call_void("rex_deref_assign", { target, emit_expr(stmt.value) })
    elseif kind == "Defer" then
      -- `defer` runs at the end of the enclosing block.  The C backend
      -- maintains a defer stack; here the statement is registered and
      -- flushed by emit_block.
      ctx.defers[#ctx.defers + 1] = stmt
    else
      unsupported(stmt)
    end
  end

  emit_block = function(block)
    if not block then
      return
    end
    local saved_defers = #ctx.defers
    push_scope()
    for _, stmt in ipairs(block.statements or {}) do
      emit_stmt(stmt)
    end
    -- Flush defers registered in this block, innermost first.
    while #ctx.defers > saved_defers do
      local d = table.remove(ctx.defers)
      if d.block then
        emit_block(d.block)
      elseif d.expr then
        emit_expr(d.expr)
      end
    end
    pop_scope()
  end

  ---------------------------------------------------------------------------
  -- collect declarations

  for _, item in ipairs(ast.items or {}) do
    if item.kind == "Use" then
      local parts = item.path or {}
      local name = item.alias
      if not name then
        name = parts[#parts]
      end
      local module = parts[#parts]
      if parts[1] == "rex" then
        module = parts[2] or name
      end
      ctx.imports[name] = module
    elseif item.kind == "Struct" then
      ctx.structs[item.name] = item
    elseif item.kind == "Enum" then
      ctx.enums[item.name] = item
    elseif item.kind == "Impl" then
      ctx.methods[item.name] = ctx.methods[item.name] or {}
      for _, method in ipairs(item.methods or {}) do
        ctx.methods[item.name][method.name] = string.format(
          "rxr_m_%s_%s",
          item.name,
          method.name
        )
      end
    elseif item.kind == "Function" then
      ctx.functions[item.name] = "rxr_f_" .. item.name
    end
  end

  ---------------------------------------------------------------------------
  -- function emission

  local function start_function(signature)
    ctx.body = {}
    ctx.decls = {}
    ctx.loops = {}
    ctx.defers = {}
    ctx.scopes = { {} }
    ctx.types = { {} }
    ctx.indent = 1
    ctx.body[1] = signature .. " {"
  end

  local function finish_function()
    local lines = {}
    lines[#lines + 1] = table.remove(ctx.body, 1)
    if #ctx.decls > 0 then
      for _, d in ipairs(ctx.decls) do
        lines[#lines + 1] = string.format("    %s %s;", d.ctype, d.name)
      end
    end
    for _, line in ipairs(ctx.body) do
      lines[#lines + 1] = line
    end
    lines[#lines + 1] = "}"
    lines[#lines + 1] = ""
    ctx.out[#ctx.out + 1] = table.concat(lines, "\n")
  end

  -- Defined below, once the match emitters exist.
  local emit_function_body

  local function param_names(params, with_self)
    local out = {}
    if with_self then
      out[#out + 1] = "self"
    end
    for _, p in ipairs(params or {}) do
      if not (with_self and p.name == "self") then
        out[#out + 1] = p.name
      end
    end
    return out
  end

  local function emit_method(item, method)
    local names = param_names(method.params, true)
    local params = {}
    for _, n in ipairs(names) do
      params[#params + 1] = "W_ " .. n
    end
    start_function(
      string.format("%s(%s)", ctx.methods[item.name][method.name], table.concat(params, ", "))
    )
    for _, n in ipairs(names) do
      -- Parameters already exist as locals from the signature; binding one
      -- must not emit a second declaration in the body.
      bind(n, n)
      -- The receiver is the impl's own type, which is what makes `self.x`
      -- resolvable without a full type checker.
      bind_type(n, "struct:" .. item.name)
    end
    emit_function_body(method.body, method.return_type)
    finish_function()
  end

  -- Emit a function or method body and decide what it returns.
  --
  -- Rex functions return their trailing expression when one is present, so a
  -- body ending in a value (a bare call, or a `match` whose arms each end in a
  -- value) has to be bound to the Cmm return register.  Without this a
  -- `match`-as-expression function silently returns nil.
  emit_function_body = function(body, return_type)
    local wants_value = return_type ~= nil and return_type ~= "void" and return_type ~= "()"
    local stmts = (body and body.statements) or {}
    local last = stmts[#stmts]

    local tail_value
    if wants_value and last then
      if last.kind == "ExprStmt" then
        tail_value = last.expr
      elseif last.kind == "Match" then
        tail_value = last
      end
    end

    if not tail_value then
      emit_block(body)
      emit(string.format("return (%s);", nil_value()))
      return
    end

    -- Emit everything but the trailing value, then bind the value.
    local head = { statements = {} }
    for i = 1, #stmts - 1 do
      head.statements[i] = stmts[i]
    end
    emit_block(head)

    local dest = new_local("ret")
    if tail_value.kind == "Match" then
      emit_match_value(tail_value, dest)
    else
      emit(string.format("%s = %s;", dest, emit_expr(tail_value)))
    end
    emit(string.format("return (%s);", dest))
  end

  local function emit_function(item)
    local names = param_names(item.params, false)
    local params = {}
    for _, n in ipairs(names) do
      params[#params + 1] = "W_ " .. n
    end
    start_function(
      string.format("%s(%s)", ctx.functions[item.name], table.concat(params, ", "))
    )
    for _, n in ipairs(names) do
      bind(n, n)
    end
    emit_function_body(item.body, item.return_type)
    finish_function()
  end

  -- Methods first: struct helpers are not needed, but keeping methods before
  -- free functions matches the C backend's ordering.
  for _, item in ipairs(ast.items or {}) do
    if item.kind == "Impl" then
      for _, method in ipairs(item.methods or {}) do
        emit_method(item, method)
      end
    end
  end

  for _, item in ipairs(ast.items or {}) do
    if item.kind == "Function" then
      emit_function(item)
    end
  end

  -- Top-level statements become an init function called from the entry point.
  local top_level = {}
  for _, item in ipairs(ast.items or {}) do
    if item.kind ~= "Use"
      and item.kind ~= "Struct"
      and item.kind ~= "Enum"
      and item.kind ~= "TypeAlias"
      and item.kind ~= "Impl"
      and item.kind ~= "Function"
    then
      top_level[#top_level + 1] = item
    end
  end

  if #top_level > 0 then
    start_function("W_ rxr_init()")
    emit_block({ statements = top_level })
    emit(string.format("return (%s);", nil_value()))
    finish_function()
  end

  ---------------------------------------------------------------------------
  -- entry point
  --
  -- gmm's Cmm `main` becomes the process entry point.  The very first thing
  -- it must do is give the machine a real stack: `return` inside any callee
  -- writes through Sp, and Sp is uninitialized at program start.

  start_function("main()")
  local base = new_local("stack")
  emit(string.format('(%s) = foreign "C" rex_cmm_stack_alloc(%d);', base, stack_bytes))
  emit(string.format("Sp = %s + %d;", base, stack_bytes))
  emit(string.format("SpLim = %s;", base))
  if #top_level > 0 then
    emit("call rxr_init();")
  end
  if ctx.functions["main"] then
    emit(string.format("call %s();", ctx.functions["main"]))
  end
  emit('foreign "C" rex_cmm_wait_all();')
  emit('foreign "C" exit(0);')
  finish_function()

  ---------------------------------------------------------------------------
  -- assemble

  local header = {
    "/* GENERATED BY the Rex Cmm backend -- do not edit. */",
    "/* Compile with: gmm -o <out> <this file> rex_cmm_shim.c <runtime .c files> */",
    "",
    '#include "Cmm.h"',
    "",
    "export main;",
  }
  for _, item in ipairs(ast.items or {}) do
    if item.kind == "Function" and ctx.functions[item.name] then
      header[#header + 1] = string.format("export %s;", ctx.functions[item.name])
    end
  end
  header[#header + 1] = ""

  local parts = {}
  parts[#parts + 1] = table.concat(header, "\n")
  for _, chunk in ipairs(ctx.out) do
    parts[#parts + 1] = chunk
  end

  -- gmm's section parser accepts exactly one item per block, so every string
  -- literal gets its own `section "data" { ... }`.
  for _, entry in ipairs(ctx.string_order) do
    parts[#parts + 1] = string.format(
      'section "data" { %s: bits8[] %s; }',
      entry.label,
      cmm_string_literal(entry.text)
    )
  end
  if #ctx.string_order > 0 then
    parts[#parts + 1] = ""
  end

  return table.concat(parts, "\n")
end

return Codegen
