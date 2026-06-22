# libpeios ABI snapshot & header verification

The **hand-written `include/peios/*.h` headers are the shipping API** — they carry
the prose docs, the `@param` notes, and the layout commentary that a generated
header can't. cbindgen is used here not to *generate* that API but to **verify** it:
to prove, mechanically, that those headers never drift from the Rust
`#[no_mangle] extern "C"` surface they describe.

## Files

- **`peios-abi.h`** — the ABI *snapshot*: a doc-stripped C header generated from the
  Rust source by cbindgen. It is the machine-checked source of truth for the ABI
  (function signatures, struct layouts, data symbols). It is **checked in** so that
  regenerating it and diffing reveals any Rust-side ABI change. It is **not** part of
  the installed API — do not ship or `#include` it; include `<peios.h>` (or the
  individual `<peios/*.h>`).
- **`../cbindgen.toml`** — the generator config (tag-style structs, `usize`→`size_t`,
  the `<pkm/*.h>` includes, the `struct kacs_*` tag renames for the uapi types).
- **`../tools/verify-abi.sh`** — the verification gate (see below).

## Regenerating the snapshot

cbindgen 0.29.2:

```sh
cd libpeios
cbindgen --config cbindgen.toml --lang c -o abi/peios-abi.h .
```

Regeneration is deterministic — same Rust source + same cbindgen version → identical
output. Pinning the cbindgen version matters: a different version may format
differently and cause a spurious step-1 diff.

## Verifying

The script needs `cbindgen 0.29.2` on PATH:

```sh
cd libpeios
./tools/verify-abi.sh
```

If `cbindgen` is not installed locally, run either command under
`nix-shell -p rust-cbindgen --run '...'`.

It checks five things and exits non-zero on any mismatch:

1. **Snapshot freshness** — regenerates and diffs against the committed
   `peios-abi.h`. A diff here means the Rust ABI changed but the snapshot wasn't
   updated.
2. **Snapshot and public umbrella compile** standalone in C and C++ (every type
   reference resolves against the `<pkm/*.h>` uapi headers).
3. **Function signatures** — every public prototype, compared between `<peios.h>`
   and the snapshot via `gcc -aux-info` (compiler-canonical prototypes).
4. **Struct layouts** — `sizeof`, `_Alignof`, and every public field offset,
   compared between the two header sets.
5. **Data symbols** — the `extern` objects (the generic-mapping tables).

Steps 3 and 5 deliberately ignore differences that do **not** affect the ABI:
parameter names, `struct`/`enum` tags (opaque typedef vs tag),
`ptrdiff_t`≡`ssize_t` / `uintptr_t`≡`size_t`, and the fact that a C `enum` has
type `int`.

The verifier derives public struct fields from the cbindgen snapshot and compares
their C `offsetof` values against the hand-written headers. The only field-name
normalisation is the Rust-keyword spelling `type_` in the snapshot versus `type`
in the public C headers.

## The workflow when the ABI changes

1. Change the Rust `extern "C"` surface.
2. Regenerate `peios-abi.h` (command above) and commit it — the diff shows exactly
   what moved.
3. Update the matching hand-written `<peios/*.h>` declaration(s).
4. Run `./tools/verify-abi.sh` — green means the header and the Rust agree again.
