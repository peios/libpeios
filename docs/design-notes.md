# libpeios — design notes & status

Checkpoint record so the architecture survives context compaction. **libpeios**
is the Rust-implemented, C-ABI userspace library for the Peios kernel↔userspace
boundary (KACS access control, LCS registry, KMES events — exposed by PKM).

## Locked decisions

- **Identity:** `libpeios.so.0`, `peios_` symbols, `<peios/…>` headers. Concept-
  split modules: `security` · `token` · `access` · `file` · `process` (= KACS);
  `registry` (LCS) and `event` (KMES) come later. RSI provider → separate `librsi`.
- **Language:** Rust, `#![no_std]` + `alloc`, `panic = "abort"`, thin `extern "C"`
  shim. The C ABI is the frozen boundary; the impl language is invisible to callers.
- **Dependencies:** `peios-cabi` (the shared C-ABI substrate — see below),
  `pkm/uapi/rust` (generated ABI constants + `#[repr(C)]` structs — the Rust analog
  of `#include <pkm/*.h>`), `kacs-core` (the shared "pkm-core"; SID/SD/ACL/ACE
  build+parse), `libc` (errno constants + `abort`). **All MIT.**
- **Crate layout / `peios-cabi`:** the `no_std` C-ABI plumbing — the malloc
  `GlobalAlloc` (`LibcAllocator`), the errno slot, the `syscall`/`ioctl` wrappers, and
  the getxattr / opaque-handle / builder helpers — lives in a **shared crate
  `peios/peios-cabi/`** (its own repo), depended on by `libpeios` and (next) `librsi`
  alike. The two once-per-artifact attributes — `#[global_allocator]` and
  `#[panic_handler]` — stay in each consuming **cdylib** (gated `cfg(not(test))`),
  wiring the allocator to `peios_cabi::LibcAllocator`. libpeios re-exports
  `peios_cabi::{abi, sys}` as `crate::{abi, sys}` (zero churn in the domain modules)
  and keeps a local `error` module that re-exports the errno slot and adds the
  `KacsError`→errno mapping (`errno_for`/`fail`). The extraction was verified
  ABI-neutral: the cbindgen snapshot regenerates byte-identical, 185 symbols
  unchanged. **`librsi` is a separate repo** (registry source / RSI provider), TBD.
- **Error model:** `int` = fd / 0 on success, `-1`+errno on failure. `ssize_t` =
  byte length, getxattr-style (probe with `cap==0`; too-small non-zero → `ERANGE`,
  never a partial write). Structured results via out-params. `access_check` → 0 /
  `-1`+EACCES with the granted mask via out-param.
- **fds:** raw `int`, `O_CLOEXEC` by default.
- **Memory:** caller-buffer / two-call is the base contract. Builders are heap-
  backed and sticky-error; output via `_bytes()` (zero-copy, valid until free) or
  `_finish()` (getxattr copy). Parsers are zero-copy views (opaque fixed-size
  storage, stack-allocatable).
- **Constants:** pass the uapi names through (no `PEIOS_*` re-aliasing).
- **Build:** cargo (+ a `build.rs` for the soname); pekit layered on top for
  packaging. No meson/make. `pekit build`/`test`/`clean` are wired to cargo.
- **Tests:** `cargo test` for units (`no_std` + the `#[panic_handler]` are gated
  `cfg(not(test))` so test builds are std); Provium (Lua, in-tree
  `pkm/kernel/out/bzImage`, static-link `libpeios.a`) for live integration. Needs
  `rustup target add x86_64-unknown-linux-musl`.
- **Headers:** kept — they are the product for C/Go/non-Rust callers. **Sync model
  RESOLVED:** hand-written headers are the API; cbindgen *verifies* them against the
  Rust ABI (`cbindgen.toml` + the `abi/peios-abi.h` snapshot + `tools/verify-abi.sh`).
  See the "Header sync — DONE" entry under `## Next` and `abi/README.md`.
- **msgpack (KMES, later):** own a complete in-house codec + a raw-bytes escape hatch.

## Built so far (verified)

- `libpeios/` crate: `Cargo.toml` (cdylib+staticlib, no_std, panic=abort, own
  workspace), `build.rs` (soname `libpeios.so.0`), `src/lib.rs` (hello-world:
  `peios_abi_version` probe), `pekit.toml`. `cargo build --release` + `cargo test`
  both green; the `.so` carries the soname and exports only `peios_*`.
- `include/peios/{security,token,access,file,process}.h` + `peios.h` — the full
  KACS C ABI surface, MIT, each compiles standalone clean.
- `docs/kacs-abi-reference.md` — the KACS ABI digest (from PSD-004 v0.20).
- `kacs-core` made no_std-consumable (`pkm_alloc` `std`→`alloc`,
  `#![cfg_attr(not(test), no_std)]`, `extern crate alloc` gated off-kernel); the
  kernel build is behaviour-neutral by construction; build + tests green.
- uapi: the token-spec / session-spec / CAAP-spec wire formats plus the integrity-
  label mask and PSB mitigation bits are promoted into `<pkm/*.h>`; Rust/Go bindings
  regenerated.
- **Deps wired** (`libpeios/Cargo.toml`): `peios-uapi` (the rust uapi crate name;
  no_std, edition 2024) + `kacs-core` (default features = no_std+alloc) + `libc`
  (`default-features = false`), all path/cached, offline-clean on rustc 1.95.
- **Foundation** (`src/`): `heap.rs` — a `System`-style `#[global_allocator]` over
  libc `malloc`/`posix_memalign` (gated `cfg(not(test))`); `error.rs` —
  `KacsError`→errno (`AllocationFailure`→ENOMEM, `AccessDenied`→EACCES,
  `UserMemoryFault`→EFAULT, else EINVAL) + the thread-local errno setter;
  `abi.rs` — the getxattr-style `emit_bytes`/`emit_str` copy-out contract + a
  no-alloc `StackWriter`.
- **`security/sid.rs` — DONE & verified.** All ten `peios_sid_*` entry points
  (build / parse_string / format / integrity / logon / well_known / valid /
  length / equal / rid), encoders are libpeios-original byte assembly, inspectors
  shim onto `kacs_core::Sid`. 8 unit tests green (layout, well-known table,
  hex/decimal authority round-trip, malformed→EINVAL, probe/ERANGE, ABI static
  assert `SID_MAX_BYTES==68`). `.so` exports exactly the 10 symbols + abi_version,
  no leaks; soname `libpeios.so.0`.

- **`security/view.rs` — DONE & verified.** The SD/ACL/ACE zero-copy views
  (`peios_sd_parse` + `_view_control/owner/group/dacl/sacl`, `peios_acl_parse` +
  `_view_count/ace`, `peios_ace_view_type/flags/mask/sid/object_type/
  inherited_object_type/app_data`) over kacs-core. **View-storage design:** the
  opaque `uint64_t _opaque[N]` holds just the borrowed `(ptr,len)`
  (`SliceView`); every accessor re-derives the kacs-core type on demand —
  lifetime-free storage, and `parse` eagerly walks every ACE so accessors are
  total (never surface a mid-walk error to C). 4 unit tests (SD round-trip,
  absent components, bare-ACL + malformed, malformed-SD rejected); ABI static
  asserts pin the view sizes (64/32/32). `.so` now exports 27 `peios_*`, no leaks.

- **`security/acl_builder.rs` — DONE & verified.** Heap-backed, sticky-error ACL
  encoder (`peios_acl_builder_new/free/reset/allow/deny/audit/label/add/bytes/
  finish/error` + `struct peios_ace_spec`). Each ACE is assembled then
  **round-tripped through `kacs_core::Ace::parse`** before acceptance (bad SID /
  reserved mask bits / malformed object+claim payloads all rejected here), and
  the ACL revision escalates via `minimum_acl_revision_for_ace_type`. Fallible
  allocation throughout: `raw_new`/`raw_free` (NULL on OOM) + `try_extend`
  (`try_reserve`→ENOMEM), added to `abi.rs`; `extern crate alloc` now in
  `lib.rs`. 7 unit tests (allow/deny round-trip via the views, object-ACE raises
  revision to DS, label ACE → `S-1-16-rid`, empty ACL, sticky-error latch +
  reset, reserved-mask reject, finish ERANGE). 38 `peios_*` exported, no leaks.

- **`security/sd_builder.rs` + `security/mapping.rs` — DONE & verified.** The
  self-relative SD encoder (`peios_sd_builder_new/free/reset/owner/group/control/
  dacl/dacl_null/sacl/bytes/finish/error`, same heap-backed sticky-error shape;
  builder owns SELF_RELATIVE + DACL/SACL PRESENT bits, components validated on
  set, finished SD round-tripped through `SecurityDescriptor::parse`) and the
  generic-mask fold (`peios_access_map_generic`). 8 tests. **The `security`
  module is now complete** (minus the deferred sid-array): 51 `peios_*`, no leaks,
  no warnings, 26 unit tests green.

- **`token/builder.rs` + `token/mod.rs` — DONE & verified.** The token-spec
  builder (`peios_token_builder_*`: new/free/reset + ~22 typed setters +
  bytes/create/error) assembling the 192-byte-header `kacs_create_token` wire
  format over the `KACS_TOKEN_SPEC_OFF_*` offsets, plus the
  `peios_token_generic_mapping` **data** symbol (mirrors the kernel's
  `TOKEN_GENERIC_MAPPING`; exports as `R`). Data-area sub-encodings confirmed by
  the kernel decoder (`token_runtime.rs`): SID-attr arrays are
  `[sid_len:u32][sid][attrs:u32]`×count with **no** leading count (count is in
  the header); user/confinement SID raw; default DACL raw; supp-gids `u32`×count;
  any section order, no alignment, offset0+count0 = absent. No userspace decoder
  exists, so fields are validated at set time (SIDs/DACL parse-checked) and the
  full round-trip is a Provium test. `create()` is an honest `ENOSYS` stub until
  the syscall layer. 4 unit tests (full round-trip via an in-test re-decoder,
  empty=header-only, invalid-SID latch, create→ENOSYS). Shared `sid_valid`/
  `acl_valid`/`to_vec` hoisted (`security/mod.rs`, `abi.rs`). 77 `peios_*`, no
  leaks, no warnings, 30 tests green.

- **`sys.rs` + `token/ops.rs` — DONE (syscall layer foundation).** The kernel-call
  mechanism: `sys.rs` wraps libc `syscall()` (and later `ioctl()`) — the kernel's
  `-errno` becomes `errno`+`-1` for free, passing straight through (no
  `KacsError` remap). `token/ops.rs` realises the fd-returning calls:
  `peios_token_open_self/process/thread/peer` (syscalls 1000/1001/1002/1010),
  `peios_token_create_raw` (1003), `peios_session_destroy_empty` (1006); and
  `peios_token_builder_create` now forwards the materialized spec to
  `kacs_create_token` (ENOSYS stub removed). **Provium-tested, not unit-tested**
  (no host kernel). 83 `peios_*`, no leaks, no warnings, 29 tests green.

- **`token/query.rs` + `token/actions.rs` — DONE (ioctl-backed actions).** Added
  the `ioctl` primitive to `sys.rs`, then the full ioctl surface:
  `peios_token_query` (`KACS_IOC_QUERY`, getxattr two-call via `kacs_query_args`)
  + the typed helpers (`user`/`type`/`session_id`/`integrity`/`privileges` via a
  `query_into<T>` size-checked reader) + `struct peios_privilege_set`; and the
  transform ops `adjust_privileges`/`reset`, `adjust_groups`/`reset` (with the
  `KACS_PRIVILEGE_RESET_ALL_DEFAULTS` / `index=u32::MAX` sentinels),
  `duplicate`/`restrict`/`get_linked` (new fd via the args `result_fd` field),
  `install`/`impersonate` (no-arg), `link` (issued on `elevated_fd`),
  `adjust_default`, `set_session_id`. `restrict`'s `[deny_indices][SIDs]` payload
  packing (`pack_restrict`) is the one unit-testable piece (2 tests). **101
  `peios_*`, no leaks, no warnings, 31 tests green.** The `token` module is
  complete bar `peios_session_create` (needs the session-spec encoder) and the
  header's already-`[adv]`-deferred claims / LCS-credentials setters.

- **Loose ends — DONE.** `peios_sid_array_parse/_count/_get` (in `view.rs`):
  validates the `[count][sid_len][sid][attrs]…` blob (every SID `sid_valid`,
  exact consumption), `SliceView`-backed like the other views; 2 tests.
  `peios_session_create` (in `token/ops.rs`): the session-spec encoder
  (`[logon_type:u8][auth_pkg_len:u16][auth_pkg][user_sid_len:u32][user_sid]`,
  consumed exactly) + syscall 1004 returning the id via `id_out`; encoder is
  unit-tested (3 tests), the syscall is Provium. `cstr_bytes` hoisted to `abi.rs`
  (shared with the SID string parser). **`security` and `token` are now complete**
  (bar the header's `[adv]`-deferred claims / LCS-credentials setters). 105
  `peios_*`, no leaks, no warnings, 36 tests green.

- **`access.rs` — DONE & verified.** The AccessCheck pipeline:
  `peios_access_check` (scalar, syscall 1023) + `peios_access_check_list`
  (by-type-result-list, 1024), over a flat `struct peios_access_request`
  (`#[repr(C)]` mirror) packed into the versioned `kacs_access_check_args` by
  `build_args` (stamps `caller_size` = `size_of::<args>()`, flattens the by-value
  `kacs_generic_mapping` into its four `u32` slots, narrows `usize`→`u32` lengths
  with a clean `EINVAL`). **Verdict plumbing (confirmed against the kernel):** the
  args struct is the wire format verbatim (uapi `#[repr(C)]` + explicit pads; size
  static-asserted == 136), `caller_size` is read by the kernel from offset 0 (no
  separate length arg). Scalar 1023 = `syscall1(args)` and carries its verdict in
  the *return value* — a non-negative granted mask on grant (a `u32`, so widened
  to `c_long` it never hits libc's `[-4095,-1]` errno window), `-EACCES` on a clean
  denial, other `-errno` on error; we reshape to `0` / `-1`+`EACCES`, copying the
  kernel-written `granted_out` (+ optional `continuous_audit`/`staging_mismatch`,
  all nullable 4-byte `u32`) out on both grant and denial. List 1024 =
  `syscall3(args, results_ptr, results_count)`, returns `0` with the per-node
  verdict in each `kacs_node_result.status` (`0`/`-EACCES`) — plain pass-through;
  `count` must equal `object_tree_count`. Only `build_args` is unit-testable
  (4 tests: size==136, field-pack + mapping flatten, unset-`[adv]`-fields-zero,
  oversized-length→EINVAL); the syscalls are Provium. **The `access` module is
  complete.** 107 `peios_*` defined, no leaks, no warnings, 40 tests green.

- **`file.rs` — DONE & verified.** The KACS native-file surface:
  `peios_file_open` (1020 — marshals `kacs_open_how` via `build_open_how`; the
  `SYSCALL_DEFINE5(dirfd, path, how, howsize, status_out)` shape, `howsize` =
  `size_of::<how>()` not a `caller_size` field, `KACS_STATUS_*` via the nullable
  `status_out` ptr the kernel guards), `peios_file_get_sd`/`set_sd` (path, 1021/
  1022, `SYSCALL_DEFINE6`), `peios_fd_get_sd`/`fd_set_sd`, and
  `peios_mount_get_policy`/`set_policy` (1026/1027 over `kacs_mount_policy_args`),
  plus the `peios_file_generic_mapping` **data** symbol. **Three ABI subtleties,
  all confirmed against the kernel:** (1) *no* fd-targeted SD syscalls exist —
  the `peios_fd_*` calls reuse the path syscalls with the fd as `dirfd` + an empty
  path + `AT_EMPTY_PATH` (kernel requires that bit for an empty path, rejects it
  for a non-empty one); pinned `AT_EMPTY_PATH=0x1000` locally. (2) the kernel's
  `get_sd` returns the *needed length* and copies only when the buffer fits (no
  `ERANGE`), so `emit_len` reshapes it to the strict getxattr contract the header
  promises (`cap==0` probe; too-small → `ERANGE`, nothing written — the kernel
  already declined to copy). (3) `set_mount_policy` requires `flags`/`generation`
  == 0 (generation is kernel-managed, auto-incremented, *not* CAS) — passed
  through faithfully so the violation surfaces as the kernel's `EINVAL`. **The
  generic mapping is composed from the named uapi rights** (not magic numbers) and
  pinned by `const` asserts to the kernel's `pkm_kacs_map_file_generic_access_mask`
  values (read `0x00120089`, write `0x00120116`, execute `0x001200A0`, all
  `0x001F01FF`) — hand-verified bit-by-bit after two Explore passes *disagreed* on
  the hex. `get_mount_policy` template is getxattr-style on `tmpl_buf`
  (`out.template_sd` → buffer iff it fits, else NULL; `template_sd_len` always the
  true length, 0 = no template). 8 unit tests (mapping values, struct sizes==32,
  open-how pack + no-SD-zeroed + null-SD-with-len→EINVAL, `emit_len`
  probe/fit/ERANGE); the syscalls are Provium. Shared `u32_len` hoisted to
  `abi.rs`; `syscall5`/`syscall6` added to `sys.rs`. **The `file` module is
  complete.** 115 `peios_*` defined, no leaks, no warnings, 48 tests green.

- **`process.rs` — DONE & verified.** `peios_process_set_mitigations(pidfd,
  mitigations)` over `kacs_set_psb` (`SYSCALL_DEFINE2(int pidfd, u32 mitigations)`,
  syscall 1005) — a direct two-arg passthrough (`pidfd == -1` = caller; kernel
  validates the mask against `KACS_MIT_ALL` and expands the `KACS_MIT_CFI` legacy
  alias, so the mask is passed straight through with no client-side filtering).
  No argument struct ⇒ nothing to unit-test; Provium-only, like the fd-returning
  token opens. **The `process` module — and with it the entire KACS surface
  (security · token · access · file · process) — is complete.** 116 `peios_*`
  defined, no leaks, no warnings, 48 tests green.

- **Token claims + LCS credentials (`token/builder.rs`) — DONE & verified.** The
  three `[adv]`-deferred setters, closing the last gap in the KACS surface:
  `peios_token_builder_add_user_claim` / `add_device_claim` (sections 108/112 &
  116/120) and `peios_token_builder_lcs_credentials` (offset 188), plus the
  `struct peios_token_claim{_value}` / `peios_token_lcs_credentials` request
  types. **Claims** encode the MS-DTYP-style relative format —
  `[name_off][type][resv][flags][count][value_off×count][slots][ptr data][name]`,
  length-delimited entries each prefixed by `[entry_len]`, no leading count — with
  the key subtlety that `value_off[i]` points at a *slot*: a scalar slot
  (INT64/UINT64/BOOLEAN) holds the 8-byte value, a pointer slot (STRING/SID/OCTET)
  holds a further u32 offset to the data (STRING = UTF-16LE NUL-term transcoded
  from caller UTF-8; SID = raw `sid_valid` bytes; OCTET = `[len][bytes]`). Each
  claim is **round-tripped through `kacs_core::parse_claim_attribute_entry`** —
  the exact parser the kernel's token decoder calls (`token_runtime.rs`) — so
  acceptance here equals kernel acceptance (the SD/ACL-builder gold standard, now
  extended to claims). **LCS extension** = `[ver=1][resv][scope_count]
  [layer_count][16-byte GUIDs…][name_len:u32×…][UTF-8 names]`, emitted as the
  final section (kernel bounds it by EOF, exact consumption); validated client-
  side to the decoder's rules (non-nil & unique GUIDs; 1..255-byte names, no
  `/`\\`, case-insensitively unique). 5 new unit tests (claims round-trip via the
  kernel parser + byte-level slot/data decode, bad-name/bad-SID latches, LCS
  round-trip, nil-GUID / bad-name latches). **The KACS surface now has no
  unimplemented declared symbols.** Shared `cstr_bytes`/`u32_len` reused.
  119 `peios_*`, no leaks, no warnings, 52 tests green.

- **`msgpack.rs` + `<peios/msgpack.h>` — DONE & verified (KMES slice 1 of 3).**
  The in-house MessagePack codec — KMES payloads are msgpack and the kernel only
  *structurally validates* them, so userspace owns encode/decode. Three pieces:
  (1) a heap-backed sticky-error **writer** (`peios_mp_writer_*`:
  nil/bool/int/uint/float/str/bin/array/map/ext/**raw** escape hatch + bytes/error)
  emitting smallest-form integers, **big-endian** per the msgpack spec (opposite of
  the KACS little-endian formats); (2) a stack-allocatable **reader** cursor
  (`peios_mp_reader` opaque `[u64;4]` = ptr/len/pos; `peek`/typed reads/`skip`/
  `remaining`, str/bin/ext borrow into the caller buffer, reads leave the cursor
  untouched on type-mismatch); (3) **`peios_mp_validate`** whose acceptance is
  bug-for-bug matched to the kernel's `kmes_validate` — accept every type byte
  except `0xc1`, `str` must be UTF-8 (`bin`/`ext` arbitrary), exactly one
  top-level value consuming all bytes, empty rejected, nesting bounded
  (top-level = depth 1; the check is `depth >= max_depth` *before* descending, so
  K nested containers need `max_depth >= K+1`). The writer validates the whole
  buffer at `_bytes()` (catches an under-filled array/map). A single `value_step`
  walker is the structure source-of-truth shared by `skip` and `validate`. Default
  emit limit is `KMES_CONFIG_MAX_NESTING_DEPTH_DEFAULT` (32), hard ceiling 256.
  12 unit tests (scalar/float/str/bin/map/nested-array/ext round-trips; depth
  boundary; reserved-byte / trailing-garbage / truncation / bad-UTF-8 / empty
  rejection; raw escape hatch; under-filled-map latch). 31 `peios_mp_*` symbols
  (150 total), no leaks, no warnings, 64 tests green; `<peios/msgpack.h>` compiles
  standalone clean (C & C++).

- **`event/emit.rs` + `<peios/event.h>` — DONE & verified (KMES slice 2 of 3).**
  The producer side: `peios_event_emit` (syscall 1090, a thin 4-arg passthrough —
  `u16` type_len, `u32` payload_len; the kernel owns validation: `SeAuditPrivilege`
  → EPERM, zero type-len / bad msgpack → EINVAL, size caps → ENOSPC, rate limit →
  EAGAIN, bad ptr → EFAULT) and `peios_event_emit_batch` (1092) over a
  `struct peios_event_entry`. **Marshal, don't forward:** the uapi `kmes_emit_entry`
  has reserved `_pad0`/`_pad1` the kernel expects zeroed, so each caller entry is
  copied into a zeroed uapi struct (`marshal_entries`) rather than forwarding a
  caller array with indeterminate padding — and `emitted_out` is made optional (a
  throwaway local when NULL, since the raw syscall faults on NULL). `count` bounds
  (`[1, KMES_BATCH_MAX_ENTRIES]`) and null-array checked client-side. Greenfield
  `<peios/event.h>` created (emit surface; consume slice to extend it; includes
  `<pkm/kmes.h>`). Added `syscall4` to `sys.rs`. 3 unit tests (marshal copies
  fields + zeroes padding, struct sizes == 32, empty); the syscalls are Provium.
  152 `peios_*`, no leaks, no warnings, 67 tests green; header compiles standalone
  (C & C++).

- **`event/consume.rs` — DONE & verified (KMES slice 3 of 3 → KMES complete).**
  The consumer: `peios_event_attach` (syscall 1091, per-CPU fd + capacity
  out-param; EINVAL past the last CPU = the discovery idiom; needs
  `SeSecurityPrivilege`) plus the lock-free ring-buffer drain, exposed two ways
  (the architect chose both): a **high-level** `peios_event_reader`
  (open/next/wait/close/lost — owns the mmap, read position, barriers, lapping
  recovery, sequence-gap loss accounting, buffer-generation/resize re-attach, and
  the futex wait) and a **low-level** `peios_event_ring` (map/unmap + barrier-
  correct write_pos/tail_pos/generation/capacity accessors + set_need_wake +
  per-position `event_at` parse + `wait`), for callers driving their own loop.
  Plus `struct peios_event` (kernel header by value; type/payload borrow into the
  mapping). **Lock-free correctness:** mmap is `8192 + 2*capacity` (RO producer
  page + RW consumer page + the data region mapped **twice** so a wrap reads
  contiguously); metadata uses real `AtomicU{64,32,8}` with the spec's barrier
  table (acquire on write_pos/tail_pos/generation, **release** when arming
  need_wake, relaxed clearing); the futex is a **shared** `FUTEX_WAIT` on the
  producer-page counter (the mapping is `MAP_SHARED`). The drain mirrors the spec
  exactly — empty (`write_pos == read_pos`), lapping (`read_pos < tail_pos` → jump
  to tail), the torn-read re-check of tail after reading, the corruption guards,
  and `read_pos & (capacity-1)` addressing of the free-running counter. Events are
  **unaligned** (read_pos advances by arbitrary event_size), so the header is read
  byte-wise via a pure `parse_event` (the one `cargo test`-able piece; the live
  drain is Provium). 4 unit tests (valid parse + field extraction, zero-payload
  kernel event, the corruption-rejection set, struct sizes). Added a `futex_wait`
  helper (libc `SYS_futex`). 167 `peios_*` (+15), no leaks, no warnings, 71 tests
  green; `<peios/event.h>` (now full emit + consume) compiles standalone (C & C++).
  **The `event` (KMES) subsystem is complete.**

## Finding — NULL DACL is not a valid KACS encoding (header reworded ✓)

kacs-core's `parse_optional_acl` **rejects `DACL_PRESENT` with offset 0** (the
classic Windows NULL-DACL form) as `InconsistentSecurityDescriptorField`. The
kernel uses the same parser, so a NULL DACL can't cross the boundary. KACS's only
"grant everyone" encoding is an *absent* DACL (`DACL_PRESENT` clear).
`peios_sd_builder_dacl_null()` now produces that (clears any DACL → grant-all).
**Implication:** `<peios/security.h>`'s comment ("a NULL DACL, which grants all")
should be reworded — there's no distinct NULL-DACL byte form; `dacl_null` and
omitting the DACL produce identical bytes (the explicit call documents intent).
Open question for the architect: accept this (reword header), or pursue NULL-DACL
support in kacs-core (a kernel behaviour change).

## Invocation layer — DONE; mechanism reference

KACS calls cross the boundary two ways (confirmed by the architect + the ABI map):
a `SYS_KACS_*` syscall (1000–1027) obtains/mints an fd; `KACS_IOC_*` ioctls
(magic `'K'`) on that fd perform actions. The kernel returns `-errno` directly;
libc `syscall()`/`ioctl()` translate to `errno`+`-1`, matching our contract — so
the kernel's errno passes straight through (no `KacsError` remap). New fds from
ioctls arrive via the args `result_fd` field. Token fds are `O_CLOEXEC` by the
kernel. All syscall/ioctl ops are **Provium**-tested (no host kernel); only pure
arg-packing is unit-tested.

## Next

**All three kernel subsystems are now implemented** — KACS (security · token ·
access · file · process), KMES (msgpack · event emit · event consume), and LCS
(the registry client surface). **No declared symbol is unimplemented.** What's
left is cross-cutting, not new surface:

- **Header sync — DONE (cbindgen as a verification gate).** Decision resolved:
  hand-written headers stay the shipping API (they carry the prose); cbindgen
  *verifies* them. `cbindgen.toml` + a committed doc-stripped snapshot
  `abi/peios-abi.h` (the Rust-truth ABI) + `tools/verify-abi.sh`. The verifier:
  (1) regenerates the snapshot and diffs it against the committed one (Rust-drift
  gate); (2) compiles the snapshot standalone C/C++; (3) compares every public
  function signature between `<peios.h>` and the snapshot via `gcc -aux-info`;
  (4) compares every struct's `sizeof`+`_Alignof`; (5) compares the data symbols.
  Steps 3–5 ignore only ABI-irrelevant spellings (param/field names — so `type_`↔
  `type` is fine — `struct`/`enum` tags, `ptrdiff_t`≡`ssize_t`, `uintptr_t`≡`size_t`,
  enum≡int). **Result: 185 fns + 24 structs + 2 data symbols all match exactly.**
  Reconciliation also found and removed the stale `peios_abi_version` scaffold probe
  (it was exported but in no header; nothing depended on it). cbindgen 0.29.2 is not
  on PATH — run the script under `nix-shell -p rust-cbindgen --run ./tools/verify-abi.sh`
  (nixpkgs attr is `rust-cbindgen`, not `cbindgen`; the script calls `cbindgen`
  directly and errors if absent). No clang here, so the comparison uses
  `gcc -aux-info` + size probes, not an AST differ. Negative-tested (perturbing a
  signature fails the gate).
  Umbrella `<peios.h>` updated to include all 8 headers. See `abi/README.md`.
- **Provium integration pass** — stand up the live tests for every syscall/ioctl/
  mmap path across all three subsystems (`rustup target add
  x86_64-unknown-linux-musl`, in-tree bzImage). So far only pure logic is
  `cargo test`-covered.
- **`librsi`** (separate library) — the registry **source**/provider side:
  `REG_SRC_REGISTER` + the RSI framed protocol (`write_rsi_*` / `parse_rsi_*` in
  `lcs-core`). Explicitly out of libpeios.
- **`event` (KMES) — COMPLETE** (all three slices: msgpack codec · emit ·
  consume). `<peios/msgpack.h>` + `<peios/event.h>` done.
- **`registry` (LCS) — COMPLETE** (the registry **client** surface; the
  **source**/RSI-provider side — `REG_SRC_REGISTER` + the RSI framed protocol — is
  explicitly OUT, deferred to a future `librsi`, per user "not rsi"). `src/registry/`
  is a directory: `mod.rs` (shared `ioctl_struct<T>` helper) + `key.rs`,
  `value.rs`, `security.rs`, `transaction.rs`, `backup.rs`. **All 21 functions**:
  - lifecycle (5): `open_key` 1100 (syscall4), `create_key` 1101 (syscall1 +
    `reg_create_key_args`), `begin_transaction` 1102 (syscall0), `commit`
    (`REG_IOC_COMMIT` `_IO`), `txn_status` (`REG_IOC_TXN_STATUS` `_IOR`);
  - values (6): `query_value`, `set_value`, `delete_value`, `blanket_tombstone`,
    `query_values_batch`, `enum_value`;
  - key nav/metadata/security (8): `enum_subkey`, `query_key_info`, `delete_key`,
    `hide_key`, `notify`, `flush`, `get_security`, `set_security`;
  - backup (2): `backup`, `restore`.

  **Key ABI facts.** Ioctls use the kernel's own pre-encoded `REG_IOC_*` u64
  constants from `peios_uapi` (no hand-rolled `_IOC`; the header-extraction agent's
  hand-computed values were wrong — `0xC0405252` vs the real `0xC0405200`). Added
  `sys::syscall0`. Create-key `path`/`layer` are NUL-terminated (bare `layer_ptr`,
  no length); the value/key ioctls take **length-counted** name/layer, where the
  **base layer** = `layer == NULL && layer_len == 0` (a non-NULL ptr with len 0 is
  the kernel's `EINVAL`). Value names are length-counted (empty = default value).
  The `_IOWR` buffer reads (`query_value`, `query_values_batch`, `enum_value`,
  `enum_subkey`, `query_key_info`, `get_security`) use the kernel's **native
  fill-or-`ERANGE`** contract — *not* reshaped to KACS getxattr: return 0 with
  actual length(s) in the struct, or `-1`/`ERANGE` with the **required** length(s)
  written back (so a zero-capacity buffer probes); two-buffer ops report *both*
  required sizes and `ERANGE` if *either* is short. Marshalled via clean libpeios
  param/result structs (`peios_reg_value`, `peios_reg_enum_value`,
  `peios_reg_subkey`, `peios_reg_key_info`) hiding the wire structs' field reuse
  (e.g. `data_len` = in-cap & out-actual). `set_value` CAS via `expected_seq`
  (0 disables, mismatch → `EAGAIN`); `REG_TOMBSTONE` accepted as a set type.
  `set_security` passes the caller's KACS SD straight through (kernel parses), with
  a file.rs-style empty-SD `EINVAL` guard. 85 tests, **186 `T peios_` symbols
  (21 `peios_reg_*`)**, zero warnings, header compiles standalone C/C++. Registry
  allocates nothing (stack structs + ioctls) → no new leak surface.

## Deferred / open

- Header sync model — **RESOLVED: cbindgen *verifies*, headers are hand-written.**
  See the "Header sync — DONE" entry under `## Next` and `abi/README.md`.
- Token-spec / session-spec **encoders** are libpeios-original (the kernel only
  *decodes* them) — pin to the uapi `*_OFF_*` offsets + a Provium round-trip test.
- SD/ACL **builders** — **RESOLVED:** kacs-core is parse/evaluate-only (no
  SID/ACL/ACE/SD construction API). The build/encode half of `security.h` is
  libpeios-original (on `alloc::Vec` + uapi layouts + kacs-core's
  `minimum_acl_revision_*`); the parse half shims onto `Sid`/`Acl`/
  `SecurityDescriptor`. Full mapping in `security-impl-map.md`.
- pekit `[install]` syntax (`.so`→`.so.0` symlink, headers, `peios.pc`) — user to
  provide at packaging time.
- `rustup target add x86_64-unknown-linux-musl` for the Provium static build.
- Kernel internal-dedup follow-up (kacs-core constants vs the promoted uapi) — needs
  a kernel build.
- `get_sd` too-small-buffer (ABI GAP #2) — libpeios enforces the clean getxattr
  contract; confirm kernel behaviour eventually.
- Provium PKM-profile wiring (→ in-tree bzImage; musl docker build).
