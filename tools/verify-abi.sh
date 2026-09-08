#!/usr/bin/env bash
#
# verify-abi.sh — prove the hand-written <peios/*.h> headers match the Rust C ABI.
#
# The hand-written headers are the shipping API (they carry the prose docs); this
# script uses cbindgen as a drift gate. It:
#
#   1. regenerates the ABI snapshot from the Rust source and checks it is identical
#      to the committed abi/peios-abi.h  (catches a Rust ABI change that nobody
#      re-snapshotted);
#   2. compiles the snapshot and hand-written umbrella standalone in C and C++
#      (every type reference resolves against the <pkm/*.h> uapi headers);
#   3. compares every public *function signature* between the hand-written headers
#      and the snapshot, using `gcc -aux-info` for compiler-canonical prototypes;
#   4. compares every public *struct* on size, alignment, and field offsets;
#   5. compares the *data symbols* (the generic-mapping tables); and
#   6. when PEIOS_LIBRARY is set, proves that DSO exports exactly that checked
#      function-and-data surface.
#
# Steps 3 and 5 ignore only ABI-irrelevant spellings: parameter names,
# `struct`/`enum` tags (opaque typedef vs tag), `ptrdiff_t`≡`ssize_t` /
# `uintptr_t`≡`size_t`, and the fact that a C `enum` has type `int`. Step 4
# compares public struct field offsets, normalizing only the Rust-keyword field
# spelling `type_` vs the C `type`.
#
# cbindgen 0.29.2 must be on PATH. If it is not installed locally, one option is:
#   nix-shell -p rust-cbindgen --run ./tools/verify-abi.sh
# Exit status is non-zero on any mismatch.

set -euo pipefail
cd "$(dirname "$0")/.."  # libpeios crate root

SNAPSHOT=abi/peios-abi.h
REQUIRED_CBINDGEN_VERSION=0.29.2
if [[ -n "${PKM_UAPI:-}" ]]; then
  : # Explicit production-build input.
elif [[ -d ../pkm/uapi ]]; then
  PKM_UAPI=../pkm/uapi
elif [[ -d /usr/include/pkm ]]; then
  PKM_UAPI=/usr/include
else
  echo "FAIL: PKM_UAPI is unset and no PKM userspace headers were found" >&2
  exit 1
fi
[[ -f "$PKM_UAPI/pkm/pkm.h" ]] \
  || { echo "FAIL: $PKM_UAPI does not contain pkm/pkm.h" >&2; exit 1; }
INC=(-I include -I "$PKM_UAPI")
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

check_cbindgen() {
  command -v cbindgen >/dev/null 2>&1 \
    || fail "cbindgen not on PATH; install it or run \`nix-shell -p rust-cbindgen --run ./tools/verify-abi.sh\`"
  local version
  version="$(cbindgen --version | awk '{print $2}')"
  [[ "$version" == "$REQUIRED_CBINDGEN_VERSION" ]] \
    || fail "cbindgen $REQUIRED_CBINDGEN_VERSION required, found ${version:-unknown}"
}

run_cbindgen() {  # $1 = output path
  check_cbindgen
  cbindgen --config cbindgen.toml --lang c -o "$1" . 2>/dev/null
}

# Drop the cbindgen provenance comment + `extern`, then erase the ABI-irrelevant
# spelling differences so two compiler-canonical prototype sets compare cleanly.
norm_fns() {
  grep -hE 'peios_[a-z_]+ *\(' "$1" \
    | sed -E 's#^/\*[^*]*\*/ ##; s/^extern //;
              s/\bstruct //g; s/\benum [A-Za-z_][A-Za-z0-9_]*/int/g;
              s/\bptrdiff_t\b/ssize_t/g; s/\buintptr_t\b/size_t/g;
              s/ +/ /g; s/ ;$/;/; s/ $//' \
    | sort -u
}

fail() { echo "FAIL: $*" >&2; exit 1; }

# --- 1. snapshot is up to date with the Rust source ------------------------------
# The Peios production rung packages the exact generator. Debian stable carries
# an older cbindgen, so that portability rung may explicitly use "auto": it
# still verifies all header and binary ABI properties against the committed
# snapshot, while regeneration remains mandatory wherever 0.29.2 is available.
case "${PEIOS_VERIFY_SNAPSHOT:-required}" in
  required)
    run_cbindgen "$TMP/gen.h"
    diff -u "$SNAPSHOT" "$TMP/gen.h" \
      || fail "$SNAPSHOT is stale — the Rust ABI changed. Regenerate it (see abi/README.md)."
    echo "ok 1/5: snapshot is up to date with the Rust source"
    ;;
  auto)
    if command -v cbindgen >/dev/null 2>&1 \
       && [[ "$(cbindgen --version | awk '{print $2}')" == "$REQUIRED_CBINDGEN_VERSION" ]]; then
      run_cbindgen "$TMP/gen.h"
      diff -u "$SNAPSHOT" "$TMP/gen.h" \
        || fail "$SNAPSHOT is stale — the Rust ABI changed. Regenerate it (see abi/README.md)."
      echo "ok 1/5: snapshot is up to date with the Rust source"
    else
      echo "skip 1/5: exact cbindgen unavailable; verifying committed snapshot"
    fi
    ;;
  *) fail "PEIOS_VERIFY_SNAPSHOT must be 'required' or 'auto'" ;;
esac

# Hand-written TU = the umbrella header (also checks the umbrella is complete).
printf '#include <peios.h>\n'                   > "$TMP/hand.c"
printf '#include "%s/%s"\n' "$PWD" "$SNAPSHOT" > "$TMP/snap.c"

# --- 2. snapshot and umbrella compile standalone ---------------------------------
gcc "${INC[@]}" -fsyntax-only -xc   "$SNAPSHOT" || fail "snapshot does not compile as C"
g++ "${INC[@]}" -fsyntax-only -xc++ "$SNAPSHOT" || fail "snapshot does not compile as C++"
gcc "${INC[@]}" -fsyntax-only -xc   "$TMP/hand.c" || fail "hand-written umbrella does not compile as C"
g++ "${INC[@]}" -fsyntax-only -xc++ "$TMP/hand.c" || fail "hand-written umbrella does not compile as C++"
echo "ok 2/5: snapshot and hand-written umbrella compile standalone (C and C++)"

# --- 3. function signatures ------------------------------------------------------
gcc "${INC[@]}" -aux-info "$TMP/hand.aux" -c -o /dev/null "$TMP/hand.c"
gcc "${INC[@]}" -aux-info "$TMP/snap.aux" -c -o /dev/null "$TMP/snap.c"
norm_fns "$TMP/hand.aux" > "$TMP/hand.fns"
norm_fns "$TMP/snap.aux" > "$TMP/snap.fns"
diff "$TMP/hand.fns" "$TMP/snap.fns" \
  || fail "function signature mismatch ('<' hand-written, '>' Rust snapshot)"
echo "ok 3/5: $(wc -l < "$TMP/hand.fns") function signatures match the Rust ABI"

# --- 4. struct size + alignment + field offsets ----------------------------------
# Public structs with a body (opaque handles are `typedef struct X X;`, no body).
mapfile -t STRUCTS < <(grep -oE '^struct peios_[a-z_]+ \{' "$SNAPSHOT" \
                       | sed -E 's/^struct //; s/ \{//' | sort -u)
mapfile -t FIELDS < <(awk '
  /^struct peios_[a-z_]+ \{/ { s=$2; next }
  s && /^};/ { s=""; next }
  s && /;/ {
    line=$0
    sub(/;.*/, "", line)
    if (line ~ /\(\*[[:space:]]*[A-Za-z_][A-Za-z0-9_]*\)/) {
      sub(/^.*\(\*[[:space:]]*/, "", line)
      sub(/[[:space:]]*\).*$/, "", line)
      field=line
    } else {
      gsub(/\[[^]]*\]/, "", line)
      sub(/^[[:space:]]*/, "", line)
      n=split(line, parts, /[[:space:]*]+/)
      field=parts[n]
    }
    if (field != "") print s, field
  }
' "$SNAPSHOT")
{
  printf '#include <stdio.h>\n#include <stddef.h>\n'
  printf 'HEADERS\nint main(void){\n'
  for s in "${STRUCTS[@]}"; do
    printf '  printf("%s %%zu %%zu\\n", sizeof(struct %s), _Alignof(struct %s));\n' "$s" "$s" "$s"
  done
  for sf in "${FIELDS[@]}"; do
    s=${sf%% *}
    f=${sf#* }
    printf '  printf("%s.%s %%zu\\n", offsetof(struct %s, %s));\n' "$s" "$f" "$s" "$f"
  done
  printf '  return 0;\n}\n'
} > "$TMP/size.tmpl"

# Materialize the two probes (substitute the header line).
sed 's#^HEADERS$#\#include <peios.h>\n\#define type_ type#' "$TMP/size.tmpl" > "$TMP/size_hand.c"
sed "s#^HEADERS\$#\#include \"$PWD/$SNAPSHOT\"#"           "$TMP/size.tmpl" > "$TMP/size_snap.c"
gcc "${INC[@]}" -o "$TMP/size_hand" "$TMP/size_hand.c"
gcc "${INC[@]}" -o "$TMP/size_snap" "$TMP/size_snap.c"
"$TMP/size_hand" | sort > "$TMP/size_hand.txt"
"$TMP/size_snap" | sort > "$TMP/size_snap.txt"
diff "$TMP/size_hand.txt" "$TMP/size_snap.txt" \
  || fail "struct layout mismatch ('<' hand-written, '>' Rust snapshot)"
echo "ok 4/5: ${#STRUCTS[@]} struct layouts match (size + alignment + field offsets)"

# --- 5. data symbols -------------------------------------------------------------
grep -hoE 'extern [^;]*peios_[a-z_]+ *;' include/peios/*.h \
  | sed -E 's/ +/ /g' | sort -u > "$TMP/hand.data"
grep -hoE 'extern [^;]*peios_[a-z_]+ *;' "$SNAPSHOT" \
  | sed -E 's/ +/ /g' | sort -u > "$TMP/snap.data"
diff "$TMP/hand.data" "$TMP/snap.data" \
  || fail "data-symbol mismatch ('<' hand-written, '>' Rust snapshot)"
echo "ok 5/5: $(wc -l < "$TMP/hand.data") data symbol(s) match"

if [[ -n "${PEIOS_LIBRARY:-}" ]]; then
  [[ -f "$PEIOS_LIBRARY" ]] || fail "PEIOS_LIBRARY does not exist: $PEIOS_LIBRARY"
  command -v nm >/dev/null 2>&1 || fail "nm not on PATH"
  {
    sed -n -E 's/.*[ *](peios_[a-z_]+) \(.*/\1/p' "$TMP/hand.fns"
    sed -n -E 's/.* (peios_[a-z_]+) *;/\1/p' "$TMP/hand.data"
  } | sort -u > "$TMP/expected.exports"
  nm -D --defined-only --format=posix "$PEIOS_LIBRARY" \
    | awk '{print $1}' | sort -u > "$TMP/actual.exports"
  diff "$TMP/expected.exports" "$TMP/actual.exports" \
    || fail "DSO export mismatch ('<' checked headers, '>' shared object)"
  echo "ok 6/6: $(wc -l < "$TMP/actual.exports") DSO exports match the checked ABI"
fi

echo
echo "ABI VERIFIED: Rust, the hand-written headers, and requested binary surface agree."
