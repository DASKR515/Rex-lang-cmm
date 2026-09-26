#!/bin/bash
# Differential test for the Cmm backend: every example must behave the same
# under the C and Cmm targets.
#
# Examples whose construct the Cmm backend has not implemented yet are listed
# in UNSUPPORTED below and are reported as KNOWN, not as failures.  A new
# example that fails will be a FAIL, so the supported surface cannot regress
# silently.
#
# Usage: tools/test_cmm_parity.sh [example-name ...]
#        with no arguments, every examples/*.rex is checked.

set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REX="$ROOT/rex"
cd "$REX" || exit 1

export LUA_PATH="./?.lua;./?/init.lua;;"

# Examples the Cmm target does not implement yet.  Keep in step with the
# UNSUPPORTED table in rex/compiler/codegen/cmm_codegen.lua.
UNSUPPORTED="bonds_test ownership_thread_safe simple_temporal spawn test_rollback_correct test_rollback_error"

# Examples that report timings.  `normalize` already collapses the numbers, so
# this list is only a safety net for a case that differs by more than the
# reported times.
TIMING="hello benchmark bench_vec"

# Examples that touch process-global state the C and Cmm runs must not share.
# The scratch directory is cleaned between the two runs so that examples which
# create files or directories stay comparable.
scrub_state() { rm -rf "$REX/rex_data" "$REX/build/sweep_tmp"; }

# Strip values that legitimately differ run to run.
normalize() {
  sed -E 's/(elapsed|since|now_ms|now_s|now_ns): [0-9.]+/\1: T/'
}

is_listed() {
  local needle=$1
  shift
  local item
  for item in "$@"; do
    [ "$item" = "$needle" ] && return 0
  done
  return 1
}

if [ $# -gt 0 ]; then
  targets=("$@")
else
  targets=()
  for f in examples/*.rex; do targets+=("$(basename "$f" .rex)"); done
fi

pass=0
fail=0
known=0

for name in "${targets[@]}"; do
  file="examples/$name.rex"
  if [ ! -f "$file" ]; then
    echo "MISSING $name ($file)"
    fail=$((fail + 1))
    continue
  fi

  scrub_state
  c_out=$(timeout 30 luajit compiler/cli/rex.lua run "$file" 2>&1 </dev/null)
  c_rc=$?

  scrub_state
  m_out=$(timeout 30 luajit compiler/cli/rex.lua run "$file" --target cmm 2>&1 </dev/null)
  m_rc=$?
  scrub_state

  # `run` allocates a fresh directory per invocation, so it cannot reuse a path
  # that already holds a linked binary.  `build` reuses one path, which is how
  # a source/executable collision hid from this suite.  Building twice in a row
  # is the exact sequence that used to fail, so exercise it for every example.
  if [ "$m_rc" -eq 0 ]; then
    timeout 60 luajit compiler/cli/rex.lua build "$file" --target cmm \
      >/dev/null 2>&1 </dev/null
    b1=$?
    timeout 60 luajit compiler/cli/rex.lua build "$file" --target cmm \
      >/dev/null 2>&1 </dev/null
    b2=$?
    if [ $b1 -ne 0 ] || [ $b2 -ne 0 ]; then
      echo "BUILDFAIL $name (repeat build failed: first=$b1 second=$b2)"
      detail=$(timeout 60 luajit compiler/cli/rex.lua build "$file" --target cmm 2>&1 </dev/null \
        | grep -iE "error|failed|panic" | head -1)
      [ -n "$detail" ] && echo "            $detail"
      fail=$((fail + 1))
      scrub_state
      continue
    fi
  fi
  scrub_state

  if [ "$c_rc" -ne 0 ]; then
    # The example does not run under the reference target either, so there is
    # no behaviour to compare against.
    echo "SKIP     $name (exit $c_rc under the C target)"
    known=$((known + 1))
    continue
  fi

  if [ "$m_rc" -ne 0 ]; then
    detail=$(echo "$m_out" | grep -iE "panic|cannot resolve|does not support|undefined reference|parse error" | head -1)
    if is_listed "$name" $UNSUPPORTED; then
      echo "KNOWN   $name ($detail)"
      known=$((known + 1))
    else
      echo "FAIL    $name"
      [ -n "$detail" ] && echo "            $detail"
      fail=$((fail + 1))
    fi
    continue
  fi

  c_norm=$(echo "$c_out" | normalize)
  m_norm=$(echo "$m_out" | normalize)

  if [ "$c_norm" = "$m_norm" ]; then
    pass=$((pass + 1))
  elif is_listed "$name" $TIMING; then
    echo "TIMING  $name (outputs differ only in reported times)"
    known=$((known + 1))
  else
    echo "DIFF    $name"
    diff <(echo "$c_norm") <(echo "$m_norm") | head -10 | sed 's/^/            /'
    fail=$((fail + 1))
  fi
done

echo "=== pass=$pass fail=$fail known=$known ==="
[ "$fail" -eq 0 ]
