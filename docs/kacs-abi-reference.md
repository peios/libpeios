# KACS Userspace ABI — Quick Reference

**Status:** Derived reference digest — *not* authoritative. PSD-004 (KACS) v0.20 is the source of truth; the `pkm/uapi/pkm/*.h` headers are the byte-level contract.
**Source:** Extracted from `learn/specs/psd-004--kacs/v0.20/` on 2026-06-14.
**Purpose:** Working ABI reference for designing/implementing libpeios's KACS modules (`<peios/security.h>`, `<peios/token.h>`, `<peios/access.h>`, `<peios/file.h>`). The uapi headers define the constants and the struct-based argument layouts; this digest fills in the *scalar syscall calling conventions* and *semantics* the headers don't carry. Re-verify against the spec before relying on any single fact here — see the GAPS section for known soft spots.

**Global conventions:** LP64/x86_64, little-endian *except* SID `IdentifierAuthority` (big-endian, 48-bit). Success ≥ 0, failure = `-errno`. No PKM-specific errnos. Token-fd ioctl magic `'K'` = `0x4B`. Syscall numbers: KACS 1000–1027.

> Errno note: the spec documents errnos inline and unevenly; there is no exhaustive per-call errno table. Standard Linux errnos for bad fds/pidfds/pointers (`EBADF`, `ESRCH`, `EFAULT`) are mostly implied, not enumerated.

---

## Part 1 — Syscalls

### 1000 `kacs_open_self_token` (§13.1, §4.8)
`long kacs_open_self_token(unsigned int flags, u32 access_mask)`
- `flags`: `KACS_REAL_TOKEN`=0x01 → primary token even while impersonating; 0 → effective token.
- `access_mask`: desired token-handle rights (`KACS_TOKEN_*`).
- Returns: token fd (≥0); fd caches the **granted** mask (AccessCheck of caller's effective token vs the target token's own SD).
- Privilege: none. The default token SD grants QUERY + adjustment rights to the user SID, so self-query always works.

### 1001 `kacs_open_process_token` (§13.1, §4.8)
`long kacs_open_process_token(int pidfd, u32 access_mask)`
- Opens the **primary** token of the process named by `pidfd`. Live reference (mutable fields visible).
- THREE checks (all required): `PROCESS_QUERY_INFORMATION` (0x0400) on target process SD; PIP dominance over target; `access_mask` vs the token's own SD.
- Returns: token fd with cached granted mask.

### 1002 `kacs_open_thread_token` (§13.1, §13.4)
`long kacs_open_thread_token(int pidfd, int tid, u32 access_mask)`
- If thread `tid` is impersonating → its **impersonation** token; else the process primary token.
- Same three checks as 1001. Returns token fd with cached granted mask.

### 1003 `kacs_create_token` (§13.1, §4.4)
`long kacs_create_token(const void *spec, size_t len)`
- Mints a token from the **token-spec wire format** (`TOKEN_SPEC_VERSION=2`; 192-byte fixed header + variable sections; min 192, max 65536). Layout in Part 4.
- Requires **SeCreateTokenPrivilege**. Returned fd **always** carries fixed mask `TOKEN_ALL_ACCESS` (0x000F01FF) — no desired-access param.
- Kernel generates: `token_id`, `token_guid` (UUIDv4), `modified_id`=token_id, `created_at`, `elevation_type`=Default, logon SID `S-1-5-5-{session_id>>32}-{session_id&0xFFFFFFFF}` (injected into groups with MANDATORY|ENABLED_BY_DEFAULT|ENABLED|LOGON_ID). `enabled_by_default` initialized = `privs_enabled`.
- Caller MUST NOT include the logon SID. `owner_sid_index`/`primary_group_index` are relative to caller groups (0=user SID, 1..N=caller groups[N-1]), excluding injected logon SID.
- Validation (all-or-nothing): SeCreateToken held; SIDs well-formed; owner = user SID or SE_GROUP_OWNER group; primary group = user SID or a token group; `session_id` references an existing session; Primary ⟹ impersonation_level=Anonymous; `write_restricted`⟹`user_deny_only`; `isolation_boundary`⟹`confinement_sid` present; wire `_reserved1` (elevation_type) MUST be 0; caller groups + injected logon SID ≤ 1024; LCS extension (if present) structurally valid. Kernel MUST NOT authenticate/resolve SIDs.
- Errno: `-EINVAL` structural/validation; `-EPERM` missing privilege.

### 1004 `kacs_create_session` (§13.1, §4.7)
`long kacs_create_session(const void *spec, size_t len)`
- Creates a logon session from the **session wire format**: `[logon_type:u8][auth_pkg_len:u16][auth_pkg:UTF-8][user_sid_len:u32][user_sid:SID]` (min 15, max 4096). `auth_pkg` empty or valid UTF-8 (else `-EINVAL`).
- Logon types: Interactive=2, Network=3, Batch=4, Service=5, NetworkCleartext=8, NewCredentials=9.
- Requires **SeTcbPrivilege**. Returns: **session ID** = u64 LUID (≥0). Auto-derives logon SID `S-1-5-5-{id>>32}-{id&0xFFFFFFFF}`.
- A session = lightweight kernel bookkeeping (LUID, logon type, user SID, auth-pkg name, ctime). No access decision consults the session.

### 1005 `kacs_set_psb` (§13.1, §5.2)
`long kacs_set_psb(int pidfd, u32 mitigations)`
- `pidfd`=-1 → self. Sets **mitigation** bits only, one-way (can only turn ON). Bits: WXP=0x001, TLP=0x002, LSV=0x004, CFI=0x008 (legacy → CFIF+CFIB), UI_ACCESS=0x010, NO_CHILD=0x020, CFIF=0x040, CFIB=0x080, PIE=0x100, SML=0x200, ALL=0x3FF.
- PIP fields NOT settable here — fixed at exec from binary signature.
- Self → no privilege. Other → `PROCESS_SET_INFORMATION` (0x0200) on target SD + PIP dominance.
- Activation-backed: setting a bit must activate/verify the underlying protection or the whole call fails closed (no mutation). wxp/tlp/lsv fail if existing mappings already violate the invariant.

### 1006 `kacs_destroy_empty_session` (§13.1, §4.7)
`long kacs_destroy_empty_session(u64 session_id)`
- Requires **SeTcbPrivilege**. Succeeds only if the session exists AND has zero live tokens AND no linked-token state AND no in-flight reference. Emits `logon-session-destroyed` KMES event.
- Errno: `-ENOENT` nonexistent; `-EBUSY` any live token / linked-token state / in-flight ref.

### 1010 `kacs_open_peer_token` (§13.1, §4.8)
`long kacs_open_peer_token(int conn_fd)`  *(named `sock_fd` in §13.1 — naming inconsistency)*
- Extracts the peer identity snapshot captured at `connect()` from a connected **Unix SOCK_STREAM/SOCK_SEQPACKET** socket. No desired-access param.
- Returns: token fd with **fixed** mask `TOKEN_QUERY | TOKEN_IMPERSONATE` (0x000C).
- Datagram, socketpair, SCM_CREDENTIALS/SCM_SECURITY produce NO peer token in v0.20 → `-EACCES`.

### 1011 `kacs_impersonate_peer` (§13.1, §9)
`long kacs_impersonate_peer(int conn_fd)`
- open+impersonate+close combined. Two-gate model (Part 5). If a gate caps the level, it's **silently reduced** — still returns 0. Overwrites any existing impersonation.
- Errno: `-EPERM` for restricted-server→unrestricted-client same-user impersonation (sandbox-escape guard). `-EACCES` if no captured KACS peer token (use explicit token fd + `KACS_IOC_IMPERSONATE`).

### 1012 `kacs_revert` (§13.1, §9.3)
`long kacs_revert(void)` — restores the calling thread to its primary token. No privilege. Returns 0 always (incl. when not impersonating).

### 1013 `kacs_set_impersonation_level` (§13.1, §9.1)
`long kacs_set_impersonation_level(int sock_fd, u32 level)`
- Called by the **client** on an **unconnected** Unix stream/seqpacket socket before `connect()`. Sets the max level a server MAY use.
- `level`: ANONYMOUS=0, IDENTIFICATION=1, IMPERSONATION=2, DELEGATION=3. Default if never called = IMPERSONATION.

### 1020 `kacs_open` (§13.1, §11)
`long kacs_open(int dirfd, const char *path, struct kacs_open_how *uhow, size_t howsize, u32 *status_out)`
- `dirfd`: base dir / AT_FDCWD. `uhow`: `struct kacs_open_how` (Part 4); `howsize` is openat2-style (min 16, copy-min + zero-fill, trailing bytes beyond kernel struct MUST be 0 → else `-EINVAL`). `status_out`: out u32, or NULL.
- **create_disposition**: SUPERSEDE=0, OPEN=1, CREATE=2, OPEN_IF=3, OVERWRITE=4, OVERWRITE_IF=5.
- **create_options**: DIRECTORY=0x0001 (non-dir → `-ENOTDIR`), DELETE_ON_CLOSE=0x0002 (regular files only; needs DELETE on file or FILE_DELETE_CHILD on parent). Other bits → `-EINVAL`.
- **flags**: only AT_SYMLINK_NOFOLLOW=0x100 defined (terminal symlink → `-ELOOP`).
- **status_out**: OPENED=1, CREATED=2, OVERWRITTEN=3, SUPERSEDED=4. A SUPERSEDE that hits a missing target reports CREATED.
- **Returned fd**: ordinary readable/writable Linux file fd. **Caches the granted access mask** in `file->f_security.granted` (immutable for fd lifetime); later ops checked `(granted & required)==required`. fd transfer (dup/fork/SCM_RIGHTS/pidfd_getfd/exec) preserves the granted mask → capability delegation.
- **Strict mode**: every concrete bit in `desired_access` MUST be granted or open fails. MUST include ≥1 data right (READ_DATA/WRITE_DATA/APPEND_DATA) or EXECUTE (defines f_mode). MAXIMUM_ALLOWED may combine with ≥1 concrete data/execute bit (those must be granted) → cached mask = AccessCheck maximum; MAXIMUM_ALLOWED alone → `-EINVAL`. FILE_DELETE_CHILD in desired_access → `-EOPNOTSUPP` (parent-dir right).
- **Creator SD**: supplying sd on OPEN_IF/OVERWRITE/OVERWRITE_IF that resolves to an *existing* object → `-EINVAL`. On create: kernel computes the new SD (inherited or caller-supplied), then runs the strict AccessCheck against that NEW SD; failure rolls back creation. Creator SD owner must be caller's SID / SE_GROUP_OWNER group unless SeRestore; creator SACL ⟹ SeSecurity; explicit label ⟹ ≤ caller integrity unless SeRelabel. New inode mode fixed: files 0600, dirs 0700. KACS-native create does NOT make FIFOs/sockets/devices/symlinks.

### 1021 `kacs_get_sd` (§13.1, §11.5)
`long kacs_get_sd(int dirfd, const char *path, u32 security_info, void *buf, u32 buf_len, u32 flags)`
- **Target**: a path relative to `dirfd` (AT_FDCWD ok). With `flags & AT_EMPTY_PATH` (0x1000), operates on the **fd itself** (path ignored). AT_SYMLINK_NOFOLLOW (0x100) targets the symlink object itself.
- `security_info`: OWNER=0x01, GROUP=0x02, DACL=0x04, SACL=0x08, LABEL=0x10. Required right: OWNER/GROUP/DACL/LABEL → READ_CONTROL; SACL → ACCESS_SYSTEM_SECURITY.
- **Output**: one self-relative SD *subset* (only requested components; absent components omitted, PRESENT bit clear).
- **Return value = total SD size in bytes, ALWAYS** (even on probe). `buf_len=0` is the **size-probe** (writes nothing). **`-ERANGE` is NOT used.** *(Behavior for a non-zero-but-too-small buffer is under-specified — see GAPS #2.)*
- Constraint: SACL and LABEL MUST NOT be requested together → `-EINVAL`.
- **AT_EMPTY_PATH fd-type dispatch**: file fd → checks required right vs fd's cached granted mask (no AccessCheck); O_PATH fd → live AccessCheck vs file SD; pidfd → process SD (live check); token fd → token's own SD (live check; the token fd's cached mask is for ioctls, NOT SD queries).
- Missing-SD: depends on mount policy (deny vs synthesize).

### 1022 `kacs_set_sd` (§13.1, §11.6, §3.7)
`long kacs_set_sd(int dirfd, const char *path, u32 security_info, const void *sd_buf, u32 sd_len, u32 flags)`
- Same target model as get_sd. Only `security_info` components are read from `sd_buf`; unindicated components preserved. Structural validation (parseable, well-formed ACEs, valid SIDs, ≤65535 bytes). After merge, result MUST have non-null owner (group may be null).
- **Required rights**: OWNER → WRITE_OWNER; GROUP → WRITE_OWNER; DACL → WRITE_DAC; SACL → ACCESS_SYSTEM_SECURITY; LABEL → WRITE_OWNER + integrity constraints.
- **Ownership**: new owner must be caller's SID or an SE_GROUP_OWNER token group. SeTakeOwnership → own SID regardless of DACL. SeRestore → ANY arbitrary SID (skips the own-SID/SE_GROUP_OWNER check).
- **Label**: without SeRelabel, settable label ≤ caller integrity. No SACL component → clears explicit label → default Medium/no-write-up; present SACL MUST contain exactly one non-inherit-only SYSTEM_MANDATORY_LABEL_ACE and no other ACEs (replaces explicit label; non-label SACL ACEs preserved). SACL component otherwise **replaces the entire SACL**. SACL+LABEL together → `-EINVAL`.
- **Mandatory resource-attribute protection**: removing/modifying a SYSTEM_RESOURCE_ATTRIBUTE_ACE with CLAIM_SECURITY_ATTRIBUTE_MANDATORY (0x0020) requires SeTcb.
- **SeRestore bypass** fires in the AccessCheck pipeline (grants WRITE_OWNER/WRITE_DAC/ACCESS_SYSTEM_SECURITY) ONLY when set_sd runs a live AccessCheck — i.e. O_PATH+AT_EMPTY_PATH, pidfd, token-fd+AT_EMPTY_PATH, or path. On a normal (non-O_PATH) file fd the cached mask is checked (no AccessCheck) → SeRestore has NO effect → backup/repair must use O_PATH+AT_EMPTY_PATH.

### 1023 `kacs_access_check` (§13.1, §10.10)
`long kacs_access_check(struct kacs_access_check_args *uargs)`
- One arg: versioned `struct kacs_access_check_args` (136 bytes; min v1 = 40; copy-min + zero-fill). Layout in Part 4.
- **Returns the granted access mask directly** (≥0). `-EACCES` if any requested right denied. `-EINVAL` for object_tree_count>1024, local_claims_len>65536, audit_context>4096, bad tree, nonzero pads; `-EFAULT` bad out-pointers.
- Key inputs: `token_fd` (-1 = caller's effective token), `sd_ptr/sd_len`, `desired_access`, caller-supplied GenericMapping 4-tuple (object-class specific), `self_sid` (PRINCIPAL_SELF S-1-5-10 substitution), `privilege_intent` (BACKUP=0x01/RESTORE=0x02), `object_tree` (flat preorder array), `local_claims` (@Local claim array), `pip_type/pip_trust` (0 = use the process PSB; non-zero = what-if/broker eval), `audit_context` (opaque object id for emitted KMES audit events).
- Outputs (all written even on `-EACCES`): `granted_out_ptr` (u32; = return value), `continuous_audit_out_ptr` (OR of matching SACL+CAAP alarm masks), `staging_mismatch_out_ptr` (1 if staged CAAP result differs from effective).
- Runs the **full** AccessCheck pipeline (Part 6) incl. privilege-use tracking and SACL audit walk. With a tree, returns the **root** node's granted mask. Advisory — gates nothing in-kernel; enforcement always uses the PSB pip.

### 1024 `kacs_access_check_list` (§13.1, §10.10)
`long kacs_access_check_list(struct kacs_access_check_args *uargs, struct kacs_node_result *results, u32 results_count)`
- Same args struct, but the **object-type list is mandatory**. `results` = output array of `struct kacs_node_result {u32 granted; s32 status}` (8 bytes), one per node in preorder; `results_count` MUST equal `object_tree_count` → else `-EINVAL`.
- Returns 0/`-errno`. Per node: `status` 0=granted / -EACCES=denied; node granted iff `(node.granted & mapped_desired)==mapped_desired`. One node's denial fails only that node. `granted_out_ptr` still receives the root's granted mask. (This is `AccessCheckByTypeResultList`.)

### 1025 `kacs_set_caap` (§13.1, §10.8)
`long kacs_set_caap(const void *policy_sid, u32 policy_sid_len, const void *spec, u32 spec_len)`
- Pushes/replaces/removes a Central Access & Auditing Policy in the kernel policy cache. `spec`=NULL or `spec_len`=0 → **remove**. Non-NULL for existing SID → replace.
- Requires **SeTcbPrivilege** (checked before parsing).
- **CAAP wire format**: `[version:u8=0x01][rule_count:u32le]` then per rule `[applies_to_len:u32le][applies_to_expr][effective_dacl_len:u32le (≠0)][effective_dacl][effective_sacl_len:u32le][effective_sacl][staged_dacl_len][staged_dacl][staged_sacl_len][staged_sacl]`. Limits: spec_len ≤256 KB; rule_count ≤256; each ACL ≤65535; applies_to ≤64 KB; version MUST be 0x01. `applies_to` = conditional-ACE bytecode ("artx" prefix), structurally valid at ingestion.
- Errno: `-EINVAL` on unknown version, effective_dacl_len=0, malformed applies_to, parse error.

### 1026 `kacs_get_mount_policy` (§13.1, §11.5)
`long kacs_get_mount_policy(int fd, struct kacs_mount_policy_args *uargs, size_t argsize)`
- `fd`: any fd (incl. O_PATH) on the target superblock. `argsize` copy-min (min 16, trailing must be 0). Requires **SeTcbPrivilege**.
- Writes back `policy`, `flags`, `generation`, `template_sd_len`. Template is a two-call size-probe: if `template_sd_ptr` non-null and `template_sd_len` large enough, copies bytes; else succeeds, writes required length, copies nothing.

### 1027 `kacs_set_mount_policy` (§13.1, §11.5)
`long kacs_set_mount_policy(int fd, struct kacs_mount_policy_args *uargs, size_t argsize)`
- Requires **SeTcbPrivilege**. `policy` MUST be DENY_MISSING=2, SYNTHESIZE_EPHEMERAL=3, or SYNTHESIZE_PERSISTENT=4. UNMANAGED=1 is **rejected** (kernel-classifier-only). `flags`/pads MUST be 0.
- DENY_MISSING requires `template_sd_ptr==0 && template_sd_len==0`. Synthesize classes: `ptr==0,len==0` clears template; `ptr!=0` requires `len>0`, ≤64 KiB, and the bytes MUST be one structurally valid complete self-relative **file** SD. Any validation failure leaves existing policy unchanged.

---

## Part 2 — Token-fd ioctls (magic `'K'` = 0x4B)

Token fd = anon_inode `kacs-token`, O_CLOEXEC. Per-handle access mask gates each ioctl.

| # | Name | Dir | Arg struct | Required handle access (+ extra) |
|---|------|-----|-----------|------|
| 0 | QUERY | _IOWR | kacs_query_args | TOKEN_QUERY (0x0008) |
| 1 | ADJUST_PRIVS | _IOW | kacs_adjust_privs_args | TOKEN_ADJUST_PRIVS (0x0020) |
| 2 | DUPLICATE | _IOWR | kacs_duplicate_args | TOKEN_DUPLICATE (0x0002) |
| 3 | INSTALL | _IO | — | TOKEN_ASSIGN_PRIMARY (0x0001) + SeAssignPrimaryToken |
| 4 | RESTRICT | _IOWR | kacs_restrict_args | TOKEN_DUPLICATE (0x0002) |
| 5 | LINK_TOKENS | _IOW | kacs_link_tokens_args | both fds TOKEN_DUPLICATE + SeTcb |
| 6 | GET_LINKED_TOKEN | _IOWR | kacs_get_linked_token_args | TOKEN_QUERY (0x0008) |
| 7 | ADJUST_GROUPS | _IOW | kacs_adjust_groups_args | TOKEN_ADJUST_GROUPS (0x0040) |
| 8 | IMPERSONATE | _IO | — | TOKEN_IMPERSONATE (0x0004) |
| 9 | ADJUST_DEFAULT | _IOW | kacs_adjust_default_args | TOKEN_ADJUST_DEFAULT (0x0080) |
| 10 | ADJUST_SESSIONID | _IOW | u32 | TOKEN_ADJUST_SESSIONID (0x0100) + SeTcb |

**QUERY** — `kacs_query_args` (16 B): `token_class:u32`(0), `buf_len:u32`(4; in=size, out=required/actual), `buf_ptr:u64`(8). **Two-call probe**: `buf_ptr==0 || buf_len==0` → write required size to `buf_len`, no payload, return 0. `buf_ptr!=0 && buf_len>0` but too small → write required size, no payload, return **`-ERANGE`**. Large enough → write payload + actual size, return 0. Payload range MUST NOT overlap the args struct → `-EINVAL`. Invalid class → `-EINVAL`.

Per-class output payload layouts:

| Val | Class | Payload |
|---|---|---|
| 0x01 | USER | Binary SID |
| 0x02 | GROUPS | `[count:u32le]` then per group `[sid_len:u32le][sid][attrs:u32le]` |
| 0x03 | PRIVILEGES | 32 B: `[present:u64][enabled:u64][enabled_by_default:u64][used:u64]` |
| 0x04 | TYPE | 4 B `[type:u32]` (1=Primary, 2=Impersonation) |
| 0x05 | INTEGRITY_LEVEL | Binary integrity SID `S-1-16-{rid}` |
| 0x06 | OWNER | Binary SID (from owner_sid_index) |
| 0x07 | PRIMARY_GROUP | Binary SID (from primary_group_index) |
| 0x08 | SESSION_ID | 4 B `[interactive_session_id:u32]` |
| 0x09 | RESTRICTED_SIDS | as GROUPS; count=0 if unrestricted |
| 0x0A | SOURCE | 16 B `[name:8][source_id:u64]` |
| 0x0B | STATISTICS | 40 B `[token_id:u64][auth_id:u64][modified_id:u64][type:u32][_pad:u32][expiration:u64]` |
| 0x0C | ORIGIN | 8 B `[origin:u64]` |
| 0x0D | ELEVATION_TYPE | 4 B `[type:u32]` (1=Default,2=Full,3=Limited) |
| 0x0E | DEVICE_GROUPS | as GROUPS; count=0 if none |
| 0x0F | APPCONTAINER_SID | Binary SID (confinement); **0 bytes if not confined** |
| 0x10 | CAPABILITIES | as GROUPS (confinement caps) |
| 0x11 | MANDATORY_POLICY | 4 B `[policy:u32]` (NO_WRITE_UP=0x01, NEW_PROCESS_MIN=0x02) |
| 0x12 | LOGON_TYPE | 4 B `[logon_type:u32]` (via auth_id in session table) |
| 0x13 | LOGON_SID | Binary SID `S-1-5-5-X-Y` |
| 0x14 | DEFAULT_DACL | Binary ACL; **0 bytes if none** |
| 0x15 | IMPERSONATION_LEVEL | 4 B `[level:u32]` (0–3); Primary tokens return 0 |
| 0x16 | USER_CLAIMS | claim-array wrapper `[entry_len:u32][entry]…`; empty if none |
| 0x17 | DEVICE_CLAIMS | claim-array wrapper; empty if none |
| 0x18 | PROJECTED_SUPPLEMENTARY_GIDS | `[count:u32]` then count × u32 gids |

Empty-result convention: optional SID/ACL → 0 bytes; optional SID array → `[count=0]` (4 B).

**ADJUST_PRIVS** — `kacs_adjust_privs_args` (24 B): `count:u32`(≤64, 0 invalid), `_pad:u32`(=0), `data_ptr:u64`→`kacs_priv_entry[]`, `previous_enabled:u64`(OUT). `kacs_priv_entry` (8 B): `luid:u32`(bit 0–63), `attributes:u32` (0=disable, ENABLED=0x02, REMOVED=0x04 irreversible, RESET_ALL_DEFAULTS=0x80000000). Reset sentinel: count=1, `{luid=0, attributes=RESET_ALL_DEFAULTS}` → resets `privileges_enabled` to `enabled_by_default` (does NOT restore removed). Invalid: ENABLED|REMOVED together, unknown bits, other RESET use, dup luids, enabling an absent privilege, luid >63. All-or-nothing. Bumps `modified_id`.

**DUPLICATE** — `kacs_duplicate_args` (16 B): `access_mask:u32`, `token_type:u32`(1/2), `impersonation_level:u32`(0–3), `result_fd:s32`(OUT). Deep clone. Level escalation forbidden only when source is already Impersonation (new ≤ source). New token: new id/guid, modified_id=new id, elevation_type=Default, fresh **default** SD (no custom SD — use WRITE_DAC after). `access_mask` AccessChecked vs the new token's default SD with the caller's effective token as subject.

**INSTALL** — no arg. Commits this (Primary) token as the calling **process's** primary token (whole thread group). User-SID change regenerates the process SD. Requires TOKEN_ASSIGN_PRIMARY + **SeAssignPrimaryTokenPrivilege** on the caller's real token.

**RESTRICT** — `kacs_restrict_args` (40 B): `privs_to_delete:u64`, `num_deny_indices:u32`, `num_restrict_sids:u32`, `data_len:u32`(≤65536), `flags:u32`(bit0 WRITE_RESTRICTED=0x01 → write-restricted + user_deny_only), `data_ptr:u64`, `result_fd:s32`(OUT), +4 pad. `data_ptr`: `u32[num_deny_indices]` (group indices → deny-only) then `num_restrict_sids` packed binary SIDs; `data_len` MUST match exactly. New token fd has the **same per-handle mask** as the source. Restricted: elevation_type=Default, `used` privs reset, new ids, default SD. Requires TOKEN_DUPLICATE. (FilterToken semantics.)

**LINK_TOKENS** — `kacs_link_tokens_args` (16 B): `elevated_fd:s32`, `filtered_fd:s32`, `session_id:u64`. Both Primary, same session (auth_id==session_id), same user SID. Sets elevated→Full, filtered→Limited (**only** mechanism that sets non-Default elevation_type). Requires **SeTcb** + both TOKEN_DUPLICATE. Self-link / bad role change → `-EINVAL`.

**GET_LINKED_TOKEN** — `kacs_get_linked_token_args` (4 B): `result_fd:s32`(OUT). Requires TOKEN_QUERY. Without SeTcb → deep clone at **Identification**, **TOKEN_QUERY-only** handle (inspect only). With SeTcb → full primary handle to the actual linked token. Not part of a live pair → `-ENOENT`.

**ADJUST_GROUPS** — `kacs_adjust_groups_args` (144 B): `count:u32`(≤1024, 0 invalid), `_pad:u32`(=0), `data_ptr:u64`→`kacs_group_entry[]`, `previous_state:u64[16]`(OUT bitmask). `kacs_group_entry` (8 B): `index:u32`, `enable:u32`. MANDATORY/deny-only/logon-SID groups can't be targeted; user SID can't be disabled; deny-only can't be re-enabled. Reset sentinel: `{index=0xFFFFFFFF, enable=0}`, count=1 → reset to creation-time enabled state. All-or-nothing. Bumps `modified_id`.

**IMPERSONATE** — no arg. Impersonates this (Impersonation) token on the calling thread. Two-gate model vs the caller's primary token (Part 5). Requires TOKEN_IMPERSONATE. Universal fallback for transports without socket-based impersonation.

**ADJUST_DEFAULT** — `kacs_adjust_default_args` (16 B): `dacl_ptr:u64` (3-way: 0/0=no change; ptr≠0,len>0=replace; ptr≠0,len=0=clear to null), `dacl_len:u32`(≤65536), `owner_index:u16`(0xFFFF=no change), `group_index:u16`(0xFFFF=no change). Affects future object creation only. Bumps `modified_id`.

**ADJUST_SESSIONID** — arg = bare `u32`. Pure metadata. Requires TOKEN_ADJUST_SESSIONID + **SeTcb**. Bumps `modified_id`.

---

## Part 3 — Token rights & privilege LUIDs

Token handle rights: ASSIGN_PRIMARY=0x0001, DUPLICATE=0x0002, IMPERSONATE=0x0004, QUERY=0x0008, (reserved 0x0010), ADJUST_PRIVS=0x0020, ADJUST_GROUPS=0x0040, ADJUST_DEFAULT=0x0080, ADJUST_SESSIONID=0x0100. **TOKEN_ALL_ACCESS=0x000F01FF**.

Token GenericMapping: read=`TOKEN_QUERY|READ_CONTROL`=**0x00020008**; write=`ADJUST_PRIVILEGES|ADJUST_GROUPS|ADJUST_DEFAULT|WRITE_DAC`=**0x000400E0**; execute=`TOKEN_IMPERSONATE`=**0x00000004**; all=**0x000F01FF**.

Default token SD (§4.8): Owner = creator user SID; DACL: ALLOW token's own user SID {QUERY|ADJUST_PRIVS|ADJUST_GROUPS|ADJUST_DEFAULT}; ALLOW creator TOKEN_ALL_ACCESS; ALLOW SYSTEM (S-1-5-18) TOKEN_ALL_ACCESS. If creator SID == token user SID, the creator ACE is omitted and an OWNER RIGHTS (S-1-3-4) ACE is added suppressing owner-implicit WRITE_DAC (keeps READ_CONTROL).

Privilege LUIDs (bit in u64): SeCreateToken=2, SeAssignPrimaryToken=3, SeLockMemory=4, SeIncreaseQuota=5, SeMachineAccount=6, **SeTcb=7**, **SeSecurity=8**, **SeTakeOwnership=9**, SeLoadDriver=10, SeBackup=17, SeRestore=18, SeDebug=20, **SeAudit=21**, SeChangeNotify=23, **SeImpersonate=29**, SeCreateGlobal=30, **SeRelabel=32**, SeCreateSymbolicLink=35, SeCreateJob(Peios)=62, SeBindPrivilegedPort(Peios)=63. Mask = `1<<bit`. Priv attrs: ENABLED=0x02, REMOVED=0x04, RESET_ALL_DEFAULTS=0x80000000.

---

## Part 4 — Struct & wire-format layouts

**struct kacs_access_check_args** (136 B; v1 min 40): `size`(u32,0), `token_fd`(s32,4), `sd_ptr`(u64,8), `sd_len`(u32,16), `desired_access`(u32,20), `generic_read`(u32,24), `generic_write`(u32,28), `generic_execute`(u32,32), `generic_all`(u32,36), `self_sid_ptr`(u64,40), `self_sid_len`(u32,48), `privilege_intent`(u32,52), `object_tree_ptr`(u64,56), `object_tree_count`(u32,64; ≤1024), `_pad0`(u32,68=0), `local_claims_ptr`(u64,72), `local_claims_len`(u32,80; ≤65536), `_pad1`(u32,84=0), `granted_out_ptr`(u64,88), `pip_type`(u32,96), `pip_trust`(u32,100), `audit_context_ptr`(u64,104), `audit_context_len`(u32,112; ≤4096), `_pad2`(u32,116=0), `continuous_audit_out_ptr`(u64,120), `staging_mismatch_out_ptr`(u64,128).

**struct kacs_node_result** (8 B): `granted`(u32,0), `status`(s32,4).
**struct kacs_object_type_entry** (20 B): `level`(u16,0; root=0, preorder), `_reserved`(u16,2=0), `guid`(u8[16],4). Validation: exactly one level-0 first node, no level gaps, no dup GUIDs.
**struct kacs_open_how** (32 B): `desired_access`(u32,0), `create_disposition`(u32,4), `create_options`(u32,8), `flags`(u32,12), `sd_ptr`(u64,16), `sd_len`(u32,24), `__pad`(u32,28=0). Min howsize 16.
**struct kacs_mount_policy_args** (32 B): `policy`(u32,0), `flags`(u32,4=0), `generation`(u32,8), `__pad0`(u32,12=0), `template_sd_ptr`(u64,16), `template_sd_len`(u32,24), `__pad1`(u32,28=0). Min argsize 16.

**Token wire format** (192-byte header; `version`=2; offset:size): `version`(0:4), `token_type`(4:1), `impersonation_level`(5:1), `_reserved0`(6:2=0), `integrity_rid`(8:4; 0/4096/8192/12288/16384), `mandatory_policy`(12:4), `privs_present`(16:8), `privs_enabled`(24:8; seeds enabled_by_default), `_reserved1`(32:4=0, elevation_type — MUST be 0), `projected_uid`(36:4), `projected_gid`(40:4), `audit_policy`(44:4), `expiration`(48:8; 0=none), `session_id`(56:8 = auth_id), `owner_sid_index`(64:4), `primary_group_index`(68:4), `source_name`(72:8), `source_id`(80:8), `user_sid_offset`(88:4), `groups_offset`(92:4), `groups_count`(96:4), `default_dacl_offset`(100:4), `default_dacl_len`(104:4), `user_claims_offset`(108:4), `user_claims_len`(112:4), `device_claims_offset`(116:4), `device_claims_len`(120:4), `device_groups_offset`(124:4), `device_groups_count`(128:4), `restricted_sids_offset`(132:4), `restricted_sids_count`(136:4), `confinement_sid_offset`(140:4), `confinement_sid_len`(144:4), `confinement_caps_offset`(148:4), `confinement_caps_count`(152:4), `confinement_exempt`(156:1), `write_restricted`(157:1), `user_deny_only`(158:1), `isolation_boundary`(159:1), `supp_gids_offset`(160:4), `supp_gids_count`(164:4), `restricted_device_groups_offset`(168:4), `restricted_device_groups_count`(172:4), `origin`(176:8), `interactive_session_id`(184:4), `lcs_credentials_offset`(188:4). All offset/len pairs: 0/0 = absent; variable sections lie within the buffer. Group/restricted-SID/device-group/cap entry = `[sid_len:u32][sid][attributes:u32]`. User SID = bare SID. Default DACL = binary ACL. Supp GIDs = `u32le[count]`. **LCS extension header** (16 B): `version`(0:4=1), `_reserved`(4:4=0), `scope_count`(8:4 ≤256), `private_layer_count`(12:4 ≤256); payload: scope_count×16-byte GUIDs, then private_layer_count×u32le name lengths, then concatenated UTF-8 names (1–255 bytes, no `\ / NUL`).

---

## Part 5 — Impersonation semantics (§9)

Levels: ANONYMOUS=0 (user SID S-1-5-7, Everyone enabled; no API bypasses client choice), IDENTIFICATION=1 (inspect only; **barred from AccessCheck** — pipeline step 0 denies), IMPERSONATION=2 (act locally; cascades across local IPC — default), DELEGATION=3 (local==Impersonation; adds network Kerberos forwarding via authd). Captured at `connect()`; client sets max via syscall 1013 before connect (default Impersonation). If the connecting thread is itself impersonating, that identity cascades.

Two-gate composition: start at client-set level. **Gate 1 (identity)**: server user SID == client user SID with same restriction status, OR server holds enabled SeImpersonatePrivilege. Restriction mismatch (restricted server → unrestricted client) is hard-denied `-EPERM`; other identity failures cap to Identification. **Gate 2 (integrity ceiling)**: cap if client integrity > server integrity; always enforced — SeImpersonate does NOT bypass it. Effective level = min(token's own level, gate-permitted). Both gates evaluated against the server's **primary token** (real_cred), unaffected by prior impersonation. Transports: SOCK_STREAM/SOCK_SEQPACKET for socket-based; datagram/socketpair/pipes → use `KACS_IOC_IMPERSONATE` with an explicit token fd.

---

## Part 6 — AccessCheck pipeline (semantics for builders, §10.10)

16 steps: 0 impersonation-level gate (Identification → deny); 1 input validation (null SD / null owner / bad tree → error; null *group* is valid); 2 generic mapping (map generic bits, strip MAXIMUM_ALLOWED); 3 effective privileges (clear backup/restore unless intent flag set); 4 privilege grants (ACCESS_SYSTEM_SECURITY granted iff SeSecurity; SeBackup → all GENERIC_READ-mapped bits; SeRestore → GENERIC_WRITE-mapped + WRITE_DAC|WRITE_OWNER|DELETE|ACCESS_SYSTEM_SECURITY); 5 pre-SACL walk (extract mandatory label / PIP trust label / resource attrs / scoped-policy SIDs; enforce MIC then PIP); 6 virtual group injection (S-1-3-4 if owner-match, S-1-5-10 if self_sid-match); 7 tree init; 8 normal DACL walk (owner implicit rights first, then first-writer-wins SID-matched walk); 9 post-DACL SeTakeOwnership override; 10 restricted pass (re-evaluate with restricting SIDs, intersect; write_restricted intersects only GENERIC_WRITE-mapped bits); 11 confinement pass (confinement SID set, **absolute** intersection, no owner-implicit, no privilege bypass); 12 CAAP (per scoped policy, intersect each applicable rule's effective DACL — AND-only; staged parallel); 13 privilege-use auditing; 14 audit emission (SACL + CAAP-SACL alarm-ACE walk → continuous_audit_mask); 15 result.

Granted reporting: scalar returns root/scalar granted; success = `(granted & mapped_desired)==mapped_desired` (or mapped_desired==0).

- **PIP** (§10.7): trust label SID `S-1-19-{type}-{trust}`; caller dominates iff `pip_type≥type AND pip_trust≥trust`. Non-dominant → only ACE-mask rights, everything else (incl. ACCESS_SYSTEM_SECURITY) denied, and privilege-granted bits revoked. pip_type/pip_trust come from the subject's PSB (set at exec); the access_check arg may override (0 = use PSB).
- **MIC** (§10.3): per-token NO_WRITE_UP gate; non-dominant caller (token integrity < object label) loses write-mapped bits (and read/execute per NO_READ_UP/NO_EXECUTE_UP); default unlabeled object = Medium + no-write-up; SeRelabel lets DACL grant WRITE_OWNER through MIC; MIC does NOT constrain privilege-granted bits.
- Matchers: user SID matches unless (for_allow && user_deny_only); group matches if (enabled || deny_only), excluding deny-only for allow. Restricting SIDs: presence-based, attributes ignored. Confinement set = confinement_sid + capabilities; NULL DACL still grants in the confinement pass; SACL access unreachable under confinement.

---

## Part 7 — SD / SID / ACL / ACE rules (§2, §3)

**SID**: `[Revision:u8=1][SubAuthorityCount:u8 0–15][IdentifierAuthority:u8[6] BIG-ENDIAN][SubAuthority:u32le[count]]`. Size `8 + 4*count`; min 8, max 68. Equality = exact binary match. SID_AND_ATTRIBUTES = SID + u32 attributes.

**SID/group attributes**: MANDATORY=0x01, ENABLED_BY_DEFAULT=0x02, ENABLED=0x04, OWNER=0x08, USE_FOR_DENY_ONLY=0x10, INTEGRITY=0x20, INTEGRITY_ENABLED=0x40, RESOURCE=0x20000000, LOGON_ID=0xC0000000. Allow-match needs ENABLED && !DENY_ONLY; deny-match needs ENABLED || DENY_ONLY. (SE_GROUP_INTEGRITY on a group does NOT set token integrity — that's the token's integrity_level field.)

**SD self-relative header** (20 B): `Revision:u8=1`(0), `Sbz1:u8`(1; RM control bits if RM_CONTROL_VALID), `Control:u16le`(2), `OwnerOffset:u32le`(4), `GroupOffset:u32le`(8), `SaclOffset:u32le`(12), `DaclOffset:u32le`(16). Offset 0 = absent. Control: OWNER_DEFAULTED=0x0001, GROUP_DEFAULTED=0x0002, **DACL_PRESENT=0x0004**, DACL_DEFAULTED=0x0008, **SACL_PRESENT=0x0010**, SACL_DEFAULTED=0x0020, DACL_AUTO_INHERIT_REQ=0x0100, SACL_AUTO_INHERIT_REQ=0x0200, DACL_AUTO_INHERITED=0x0400, SACL_AUTO_INHERITED=0x0800, **DACL_PROTECTED=0x1000**, **SACL_PROTECTED=0x2000**, RM_CONTROL_VALID=0x4000, **SELF_RELATIVE=0x8000** (always set for stored SDs). (0x0040 reserved; 0x0080 SE_SERVER_SECURITY → fail closed in v0.20.) Max SD 65535 B. **Null DACL** (PRESENT clear) → grants all (bounded to GENERIC_ALL-mapped). **Empty DACL** (PRESENT set, 0 ACEs) → grants nothing but owner-implicit.

**ACL header** (8 B): `AclRevision:u8`(0), `Sbz1:u8`(1), `AclSize:u16le`(2; incl header; ≥8, ≤64 KB), `AceCount:u16le`(4), `Sbz2:u16`(6). Exactly AceCount ACEs packed from offset 8, no leftover bytes. Revisions: ACL_REVISION=0x02 (basic types 0x00–0x03 + 0x11/0x12/0x13/0x14); ACL_REVISION_DS=0x04 (adds object 0x05–0x08 + callback 0x09–0x10). On create use the minimum required revision; on parse accept permissively (do NOT reject on revision/type mismatch).

**ACE header** (4 B): `AceType:u8`(0), `AceFlags:u8`(1), `AceSize:u16le`(2; **MUST be a multiple of 4**). Families:
- Single-SID (ALLOWED 0x00, DENIED 0x01, AUDIT 0x02, ALARM 0x03, MANDATORY_LABEL 0x11, SCOPED_POLICY_ID 0x13, PROCESS_TRUST_LABEL 0x14): `[header][Mask:u32@4][Sid@8..end]`.
- Object (ALLOWED_OBJECT 0x05, DENIED_OBJECT 0x06, AUDIT_OBJECT 0x07, ALARM_OBJECT 0x08): `[header][Mask@4][Flags:u32@8][ObjectType:16 if 0x01][InheritedObjectType:16 if 0x02][Sid…]`.
- Callback (0x09–0x10): single-SID/object + trailing `ApplicationData` (conditional bytecode).
- RESOURCE_ATTRIBUTE 0x12: single-SID prefix, SID MUST be Everyone S-1-1-0, ApplicationData = exactly one claim entry. COMPOUND 0x04 reserved/unused.
- Unrecognized types: silently skipped on evaluation, preserved on round-trip.

ACE flags: OBJECT_INHERIT=0x01, CONTAINER_INHERIT=0x02, NO_PROPAGATE=0x04, INHERIT_ONLY=0x08, INHERITED=0x10, SUCCESSFUL_ACCESS=0x40, FAILED_ACCESS=0x80. Object-ACE body `Flags`: OBJECT_TYPE_PRESENT=0x01, INHERITED_OBJECT_TYPE_PRESENT=0x02.

**ACE ordering**: canonical = explicit-deny, explicit-allow, inherited-deny, inherited-allow (whole-object before object-type within a category). **KACS MUST NOT reject non-canonical DACLs and MUST NOT reorder caller-supplied DACLs** — order is load-bearing (first-writer-wins). When KACS *constructs* a DACL, it emits explicit before inherited, preserving source order within each. SACL has no ordering requirement.

**Ownership** (§3.7): owner gets implicit READ_CONTROL + WRITE_DAC unless suppressed by a non-inherit-only ACE targeting OWNER RIGHTS S-1-3-4 (presence-only pre-scan). Ownership = SID equality vs user SID or token group SIDs. Transfer needs WRITE_OWNER; without SeTakeOwnership the new owner must be caller's SID or an SE_GROUP_OWNER group; SeRestore bypasses the SID constraint.

**Integrity label**: SYSTEM_MANDATORY_LABEL_ACE (0x11), SID `S-1-16-{0,4096,8192,12288,16384}` (else SD malformed), mask NO_READ_UP=0x01/NO_WRITE_UP=0x02/NO_EXECUTE_UP=0x04. First non-inherit-only label ACE is authoritative. Order System>High>Medium>Low>Untrusted.

**Claim entry** (CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1): `NameOffset:u32`(0), `ValueType:u16`(4), `Reserved:u16`(6), `Flags:u32`(8), `ValueCount:u32`(12), `ValueOffsets:u32[ValueCount]`(16). Offsets relative to entry start, LE. Types: INT64=0x01, UINT64=0x02, STRING=0x03 (UTF-16LE), SID=0x05, BOOLEAN=0x06 (u64), OCTET=0x10; FQBN=0x04 unsupported. Flags: CASE_SENSITIVE=0x02, USE_FOR_DENY_ONLY=0x04, DISABLED=0x10, MANDATORY=0x20. Multi-entry containers use the length-prefixed wrapper `[entry_len:u32le][entry]` repeated.

**File GenericMapping** (object class FILE):
- read = `FILE_READ_DATA|FILE_READ_ATTRIBUTES|FILE_READ_EA|READ_CONTROL|SYNCHRONIZE` = **0x00120089**
- write = `FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_ATTRIBUTES|FILE_WRITE_EA|READ_CONTROL|SYNCHRONIZE` = **0x00120116**
- execute = `FILE_EXECUTE|FILE_READ_ATTRIBUTES|READ_CONTROL|SYNCHRONIZE` = **0x001200A0**
- all = **0x001F01FF** (all file rights + DELETE|READ_CONTROL|WRITE_DAC|WRITE_OWNER|SYNCHRONIZE; derived — see GAPS #13)

File rights (low 16): READ_DATA/LIST_DIRECTORY=0x0001, WRITE_DATA/ADD_FILE=0x0002, APPEND_DATA/ADD_SUBDIRECTORY=0x0004, READ_EA=0x0008, WRITE_EA=0x0010, EXECUTE/TRAVERSE=0x0020, DELETE_CHILD=0x0040, READ_ATTRIBUTES=0x0080, WRITE_ATTRIBUTES=0x0100. Standard: DELETE=0x00010000, READ_CONTROL=0x00020000, WRITE_DAC=0x00040000, WRITE_OWNER=0x00080000, SYNCHRONIZE=0x00100000, ACCESS_SYSTEM_SECURITY=0x01000000, MAXIMUM_ALLOWED=0x02000000. Generic: ALL=0x10000000, EXECUTE=0x20000000, WRITE=0x40000000, READ=0x80000000. Reserved bits 21–23, 26–27 MUST NOT be used.

**Size limits**: SD ≤65535; ACL ≤64 KB; SID 8–68 B (≤15 sub-authorities); AceSize multiple of 4; token groups ≤1024 (incl. injected logon SID); object_tree ≤1024 nodes; local_claims ≤65536; audit_context ≤4096; CAAP spec ≤256 KB / ≤256 rules / each ACL ≤65535 / applies_to ≤64 KB; mount template ≤64 KiB.

---

## GAPS / Ambiguities (re-verify before relying on these)

1. **No exhaustive errno table.** Standard Linux errnos for bad pidfds/fds/pointers are mostly implied (EBADF/ESRCH/EFAULT), not enumerated, for most calls.
2. **`get_sd` non-zero-but-too-small buffer is under-specified.** Probe (buf_len=0 → writes nothing, returns size) is clear; whether a too-small *non-zero* buffer writes nothing (clean) or a truncated SD (footgun) is not stated. **Confirm before implementing the SD getter.**
3. **`set_psb` failure errnos unspecified** ("fail closed" — EPERM? EACCES? EBUSY? EINVAL?).
4. **AccessCheck denial errno for 1000–1002** stated as "`-errno`"; almost certainly `-EACCES`, not explicit.
5. ~~wire formats live only in the spec~~ **Resolved 2026-06-14:** the `create_token` token-spec, `create_session` session-spec, and `set_caap` CAAP-spec wire formats are now in the uapi — `KACS_TOKEN_SPEC_*` / `KACS_TOKEN_LCS_*` / `KACS_SESSION_SPEC_*` (`token.h`), `KACS_CAAP_SPEC_*` (`access.h`), pinned by `_Static_assert` in `smoke_test.c`. Internal dedup (kernel parsers consuming the uapi names) is a flagged follow-up, deferred until a kernel build is available.
6. **No userspace path to a token's `token_guid`** (STATISTICS is LUID-only), yet KMES event headers carry token GUIDs. Possible PKM ABI gap for event↔token correlation.
7. Invalid impersonation-level escalation errno (e.g. Identification→Impersonation) not named (EINVAL? EPERM?).
8. `get_sd`/`set_sd` rejection of AT_* flags beyond AT_EMPTY_PATH/AT_SYMLINK_NOFOLLOW unstated.
9. Syscall 1010 parameter named `conn_fd` (§13.6) vs `sock_fd` (§13.1) — same arg.
10. Whether `previous_*` out-fields are written on validation failure (ADJUST_GROUPS/PRIVS) is unstated (presumably not).
11. `set_caap` idempotency on removing a non-existent policy SID unstated (0 or error?).
12. Full `audit_policy` flag set: OBJECT_ACCESS_SUCCESS=0x01, OBJECT_ACCESS_FAILURE=0x02, PRIVILEGE_USE_SUCCESS=0x04, PRIVILEGE_USE_FAILURE=0x08 (wire-format section says "etc.").
13. **File GenericMapping `all` (0x001F01FF) is derived** from the member list, not quoted as a literal — cross-check against the kernel uapi header.
