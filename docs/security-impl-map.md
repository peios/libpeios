# `security` module — implementation map

Working reference for implementing `<peios/security.h>` as an `extern "C"` shim.
Derived from reading kacs-core `src/{sid,acl,ace,security_descriptor,access_mask,
error}.rs` on 2026-06-14.

## Key finding

**kacs-core is PARSE / EVALUATE only — no builders.** There is no
`Sid`/`Acl`/`Ace`/`SecurityDescriptor` construction or serialization API. So:

- **Parse / inspect** half of `security.h` → thin shim over kacs-core types.
- **Build / encode** half → **libpeios-original**, on `alloc::Vec` (we own the
  crate) + the uapi layout constants + kacs-core's `minimum_acl_revision_*` helpers.

## kacs-core API we shim over (verbatim)

- **`Sid<'a>`** (`sid.rs`): `parse(&[u8])->KacsResult<Sid>`, `parse_prefix->(Sid,
  usize)`, `as_bytes`, `revision`, `sub_authority_count`, `identifier_authority->
  [u8;6]`, `sub_authority(i)->Option<u32>`, `relative_identifier->Option<u32>`,
  `impl Display` (SDDL `S-…`). Consts `MIN_SIZE=8`, `MAX_SUB_AUTHORITIES=15`,
  `MAX_SIZE=68`. `SE_GROUP_*` attr consts live here. **No build, no string-parse.**
- **`Acl<'a>`** (`acl.rs`): `parse`, `parse_prefix`, `bytes`, `revision`,
  `ace_count`, `entries()->AclEntries` (yields `KacsResult<Ace>`). `HEADER_SIZE=8`.
- **`Ace<'a>` / `AceKind<'a>`** (`ace.rs`): `parse`, `parse_prefix`, `bytes`,
  `ace_type`, `ace_flags`, `ace_size`, `kind()->AceKind`. `AceKind` =
  `SingleSid{mask,sid}` | `Object{mask,flags,object_type,inherited_object_type,sid}`
  | `Callback{mask,sid,application_data}` | `CallbackObject{…}` |
  `ResourceAttribute{mask,sid,application_data}` | `Opaque`. ACE-type consts +
  `minimum_acl_revision_for_ace_type/bytes/slices` +
  `minimum_acl_revision_with_source_floor_for_opaque` — **use these to pick the ACL
  revision when building.**
- **`SecurityDescriptor<'a>`** (`security_descriptor.rs`): `parse`, `parse_layout->
  SecurityDescriptorLayout`, `from_cached_layout`, `bytes`, `control`,
  `resource_manager_control`, `owner()->Option<Sid>`, `group()`, `sacl()->
  Option<Acl>`, `dacl()`. `HEADER_SIZE=20`, `MAX_SECURITY_DESCRIPTOR_BYTES=65535`.
  `SE_*` control consts here.
- **`access_mask.rs`**: `GenericMapping{read,write,execute,all}` (kacs-core's own
  type; layout == uapi `kacs_generic_mapping`), `FILE_GENERIC_MAPPING`,
  `PROCESS_GENERIC_MAPPING` (**no TOKEN mapping**), `GenericMapping::map_mask->
  KacsResult<u32>` (folds generic + validates reserved bits), `validate_ace_mask`,
  standard/file/process/generic right consts.
- **`error.rs`**: `KacsError` (~40 variants), `KacsResult<T>`. → map to errno.

## Per-function plan

**Reuse kacs-core (parse/inspect):**
- `peios_sid_valid` → `Sid::parse(..).is_ok()`
- `peios_sid_length` → `8 + 4*bytes[1]`
- `peios_sid_equal` → byte compare
- `peios_sid_rid` → `Sid::relative_identifier`
- `peios_sid_format` → `Sid::parse` then `Display` into the caller buffer via
  `core::fmt::Write` (no alloc)
- `peios_sd_parse` + `peios_sd_view_*` → `SecurityDescriptor` + accessors
- `peios_acl_parse` + `peios_acl_view_*` + `peios_ace_view_*` → `Acl::entries` /
  `Ace` / `AceKind`
- `peios_access_map_generic` → inline fold (see gotchas)

**libpeios-original (build/encode + two parsers kacs-core lacks):**
- `peios_sid_build` / `_integrity` / `_logon` / `_well_known` → byte assembly
  (rev=1, count, id-authority big-endian, sub-authorities little-endian)
- `peios_sid_parse_string` → SDDL `S-1-…` parser (kacs-core has none)
- `peios_acl_builder_*` (`allow/deny/audit/label/add/finish/bytes/error`) → ACL
  encoder accumulating ACE bytes on `alloc::Vec`; revision via `minimum_acl_revision_*`
- `peios_sd_builder_*` → self-relative SD encoder (20-byte header + components)
- `peios_sid_array_parse/_count/_get` → `[count][sid_len][sid][attrs]…` loop (NEW)

**Constants libpeios supplies:**
- `peios_token_generic_mapping` (token.h) — NOT in kacs-core; define:
  read `0x00020008`, write `0x000400E0`, execute `0x00000004`, all `0x000F01FF`.
- `peios_file_generic_mapping` (file.h) — reuse `FILE_GENERIC_MAPPING`:
  read `0x00120089`, write `0x00120116`, execute `0x001200A0`, all `0x001F01FF`.

## Gotchas

- **GenericMapping type bridge:** the header passes uapi `struct
  kacs_generic_mapping`; kacs-core has its own same-layout `GenericMapping`.
  `peios_access_map_generic` returns plain `uint32_t` (non-failing), but kacs-core's
  `map_mask` returns `Result` and rejects reserved bits `0x0ce00000`. Do the fold
  **inline** in libpeios; the kernel validates on the real syscall anyway.
- **`peios_sid_format`:** `Sid`'s `Display` prints sub-authorities in decimal and
  the identifier-authority in decimal (≤2³²) or `0x%012x` (larger) — matches SDDL.
- **`peios_sid_parse_string`:** accepts the numeric `S-1-…` literal (strict) and,
  for non-`S-`-prefixed input, the two-letter SDDL aliases (`BA`/`SY`/`WD`/…) via
  the SDDL alias table. A malformed `S-1-…` is not rescued by the alias parser.
- **Ownership:** kacs-core owned outputs use `PkmVec`/`PkmString`; libpeios's own
  encoders can just use `alloc::Vec` directly — simpler, and we control the crate.

## error → errno (first cut; refine in impl)

`AllocationFailure`→`ENOMEM`; `AccessDenied`→`EACCES`; `UserMemoryFault`→`EFAULT`;
everything structural/validation (`Truncated`, `InvalidSid*`, `InvalidAcl*`,
`InvalidAce*`, `SecurityDescriptor*`, `Inconsistent*`, `*Overlap`,
`ReservedAccessMaskBits`, `MaximumAllowedInAce`, `InvalidClaim*`, object-type
errors)→`EINVAL`.

## Build order for the first slice

1. `error`→errno map. 2. SID: build / well_known / integrity / logon / valid /
length / equal / rid / format / parse_string. 3. SD + ACL parse views (over
kacs-core). 4. ACL builder. 5. SD builder. 6. generic mappings + fold. Unit-test
each (build↔parse round-trips, well-known SIDs, malformed→errno, ABI static-asserts).
