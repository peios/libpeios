/* SPDX-License-Identifier: MIT */
/*
 * <peios/security.h> — Peios security-descriptor vocabulary.
 *
 * SIDs, security descriptors, ACLs, and ACEs are the shared currency of every
 * KACS interface (tokens, files, access checks) and of LCS key security. They
 * cross the kernel boundary as variable-length, self-relative byte buffers in
 * the MS-DTYP wire formats; this module is the one place libpeios lifts that
 * into something safe to handle from C:
 *
 *   - SIDs are encoded, parsed, formatted, and compared with small
 *     length-returning helpers (a SID is at most PEIOS_SID_MAX_BYTES).
 *   - Security descriptors and ACLs are assembled with sticky-error *builders*
 *     and read back with zero-copy *views*.
 *
 * Wire constants (KACS_SID_*, KACS_SD_*, KACS_ACE_*, and struct
 * kacs_generic_mapping) come straight from <pkm/sid.h> and <pkm/sd.h>; libpeios
 * does not re-alias them — callers use the published ABI names directly.
 *
 * Library-wide conventions:
 *   - int returns: an fd or 0 on success; -1 with errno on failure.
 *   - ssize_t returns: a byte length, getxattr-style. Pass cap == 0 (or a NULL
 *     buffer) to probe for the required size; a too-small *non-zero* buffer
 *     fails with ERANGE and writes nothing — never a truncated result.
 *   - Builders are heap-backed and sticky-error: the void add/set calls never
 *     fail inline, the first error latches, and it surfaces at _error() or when
 *     you take the bytes. Free every builder you create.
 *   - Views borrow the buffer they parse: keep it alive and unmodified for the
 *     lifetime of the view and anything derived from it.
 */
#ifndef PEIOS_SECURITY_H
#define PEIOS_SECURITY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>		/* ssize_t */

#include <pkm/sid.h>
#include <pkm/sd.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ====================================================================== */
/* SIDs                                                                   */
/* ====================================================================== */

/* Largest encoded SID, i.e. KACS_SID_BYTE_LEN(KACS_SID_MAX_SUB_AUTHORITIES).
 * A buffer of this size always holds any valid SID; the SID helpers below
 * never require a two-call probe. */
#define PEIOS_SID_MAX_BYTES	68u

/* Well-known SIDs, selected by peios_sid_well_known(). */
enum peios_wks {
	PEIOS_WKS_NULL = 0,		/* S-1-0-0   Nobody                  */
	PEIOS_WKS_EVERYONE,		/* S-1-1-0   World                   */
	PEIOS_WKS_LOCAL,		/* S-1-2-0   Local                   */
	PEIOS_WKS_CREATOR_OWNER,	/* S-1-3-0                           */
	PEIOS_WKS_CREATOR_GROUP,	/* S-1-3-1                           */
	PEIOS_WKS_OWNER_RIGHTS,		/* S-1-3-4   suppresses owner WRITE_DAC */
	PEIOS_WKS_ANONYMOUS,		/* S-1-5-7                           */
	PEIOS_WKS_SELF,			/* S-1-5-10  PRINCIPAL_SELF          */
	PEIOS_WKS_AUTHENTICATED_USERS,	/* S-1-5-11                          */
	PEIOS_WKS_SYSTEM,		/* S-1-5-18  Local System            */
	PEIOS_WKS_LOCAL_SERVICE,	/* S-1-5-19                          */
	PEIOS_WKS_NETWORK_SERVICE,	/* S-1-5-20                          */
	PEIOS_WKS_ADMINISTRATORS,	/* S-1-5-32-544                      */
};

/* Integrity-level RIDs (the sub-authority of an S-1-16-x label SID). */
enum peios_integrity_level {
	PEIOS_IL_UNTRUSTED = 0,
	PEIOS_IL_LOW	   = 4096,
	PEIOS_IL_MEDIUM	   = 8192,
	PEIOS_IL_HIGH	   = 12288,
	PEIOS_IL_SYSTEM	   = 16384,
};

/*
 * peios_sid_build - encode a binary SID from its parts.
 * @id_authority: 48-bit identifier authority (numeric; encoded big-endian).
 * @sub_auths:    @count sub-authorities (encoded little-endian).
 * @count:        0..KACS_SID_MAX_SUB_AUTHORITIES.
 * Returns the encoded length, or -1 (EINVAL bad count; ERANGE @cap too small).
 */
ssize_t peios_sid_build(void *out, size_t cap, uint64_t id_authority,
			const uint32_t *sub_auths, unsigned count);

/* Parse the SDDL string form ("S-1-5-21-…") into a binary SID. */
ssize_t peios_sid_parse_string(void *out, size_t cap, const char *sddl);

/* Format a binary SID as its SDDL string ("S-1-…"); returns the string length
 * (excluding the NUL), getxattr-style. */
ssize_t peios_sid_format(const void *sid, size_t len, char *out, size_t cap);

/* Construct an integrity-label SID S-1-16-<rid> (see peios_integrity_level). */
ssize_t peios_sid_integrity(void *out, size_t cap, uint32_t level_rid);

/* Construct a logon SID S-1-5-5-<hi>-<lo> from a 64-bit session id. */
ssize_t peios_sid_logon(void *out, size_t cap, uint64_t session_id);

/* Construct a well-known SID (see enum peios_wks). */
ssize_t peios_sid_well_known(void *out, size_t cap, enum peios_wks which);

/* True if @sid is a structurally valid SID of exactly @len bytes. */
bool peios_sid_valid(const void *sid, size_t len);

/* Encoded length of @sid, read from its sub-authority count. Caller must have
 * already validated @sid, or bounded it to PEIOS_SID_MAX_BYTES. */
size_t peios_sid_length(const void *sid);

/* Exact binary equality (the only equality KACS defines for SIDs). */
bool peios_sid_equal(const void *a, size_t alen, const void *b, size_t blen);

/* The RID — last sub-authority — of @sid, or 0 if it has none. */
uint32_t peios_sid_rid(const void *sid, size_t len);

/* ====================================================================== */
/* Access masks                                                           */
/* ====================================================================== */

/*
 * Fold the four generic bits (KACS_ACCESS_GENERIC_*) of @mask into
 * object-specific rights using @m, and clear the generic bits. The canonical
 * per-class mappings are published as peios_file_generic_mapping (<peios/file.h>)
 * and peios_token_generic_mapping (<peios/token.h>).
 */
uint32_t peios_access_map_generic(uint32_t mask,
				  const struct kacs_generic_mapping *m);

/* ====================================================================== */
/* ACL construction                                                       */
/* ====================================================================== */

/*
 * A single ACE, general enough for every family. Fields not used by @type are
 * left NULL/0:
 *   - object ACEs (KACS_ACE_TYPE_*_OBJECT) read @object_type /
 *     @inherited_object_type (each a 16-byte GUID, or NULL if absent);
 *   - callback and resource-attribute ACEs carry trailing @app_data.
 * @sid is the trustee; @mask is the access mask; @flags are KACS_ACE_FLAG_*.
 */
struct peios_ace_spec {
	uint8_t		type;		/* KACS_ACE_TYPE_*  */
	uint8_t		flags;		/* KACS_ACE_FLAG_*  */
	uint32_t	mask;
	const void     *sid;
	size_t		sid_len;
	const uint8_t  *object_type;		/* 16 bytes, or NULL */
	const uint8_t  *inherited_object_type;	/* 16 bytes, or NULL */
	const void     *app_data;
	size_t		app_data_len;
};

typedef struct peios_acl_builder peios_acl_builder;

/* Create / destroy an ACL builder. _new() returns NULL on allocation failure. */
peios_acl_builder *peios_acl_builder_new(void);
void		   peios_acl_builder_free(peios_acl_builder *b);

/* Drop all accumulated ACEs and clear the sticky error, reusing the builder. */
void peios_acl_builder_reset(peios_acl_builder *b);

/* Convenience adders for the common single-SID families. @flags is usually 0
 * (inheritance flags apply to container/inheritable ACEs). */
void peios_acl_builder_allow(peios_acl_builder *b, const void *sid, size_t len,
			     uint32_t mask, uint8_t flags);
void peios_acl_builder_deny(peios_acl_builder *b, const void *sid, size_t len,
			    uint32_t mask, uint8_t flags);
void peios_acl_builder_audit(peios_acl_builder *b, const void *sid, size_t len,
			     uint32_t mask, uint8_t flags);

/* Append a SYSTEM_MANDATORY_LABEL ACE for integrity level S-1-16-<rid>.
 * @policy_mask is a mask of the KACS_SYSTEM_MANDATORY_LABEL_NO_{READ,WRITE,
 * EXECUTE}_UP bits (from <pkm/sd.h>). */
void peios_acl_builder_label(peios_acl_builder *b, uint32_t integrity_rid,
			     uint32_t policy_mask);

/* Append an arbitrary ACE (object / callback / resource-attribute families). */
void peios_acl_builder_add(peios_acl_builder *b, const struct peios_ace_spec *ace);

/*
 * The serialized ACL. peios_acl_builder_bytes() returns a pointer into the
 * builder valid until the next mutating call, reset, or free (NULL if the
 * sticky error is set); peios_acl_builder_finish() copies it out, getxattr-style.
 */
const void *peios_acl_builder_bytes(peios_acl_builder *b, size_t *len_out);
ssize_t	    peios_acl_builder_finish(peios_acl_builder *b, void *buf, size_t cap);

/* The latched error (an errno), or 0 if the builder is still healthy. */
int peios_acl_builder_error(const peios_acl_builder *b);

/* ====================================================================== */
/* Security-descriptor construction                                       */
/* ====================================================================== */

typedef struct peios_sd_builder peios_sd_builder;

peios_sd_builder *peios_sd_builder_new(void);
void		  peios_sd_builder_free(peios_sd_builder *b);
void		  peios_sd_builder_reset(peios_sd_builder *b);

/* Owner / group SIDs. Omit a call to leave the component absent (so an SD built
 * to set only some components via kacs_set_sd carries only what you set). */
void peios_sd_builder_owner(peios_sd_builder *b, const void *sid, size_t len);
void peios_sd_builder_group(peios_sd_builder *b, const void *sid, size_t len);

/* Set/clear control bits (KACS_SD_DACL_PROTECTED, …). SELF_RELATIVE and the
 * PRESENT bits are managed by the builder. */
void peios_sd_builder_control(peios_sd_builder *b, uint16_t set, uint16_t clear);

/*
 * DACL/SACL. Pass ACL bytes (typically from peios_acl_builder_bytes()); an ACL
 * with zero ACEs is a present-but-empty DACL (grants only owner-implicit
 * rights). KACS has no NULL-DACL (DACL_PRESENT set with a null pointer)
 * encoding — the kernel's parser rejects it — so "grant everyone" is an *absent*
 * DACL (DACL_PRESENT clear). peios_sd_builder_dacl_null() requests exactly that,
 * clearing any DACL set earlier; it therefore yields the same bytes as never
 * setting a DACL, and exists to state the grant-all intent explicitly. (Omitting
 * the DACL is also what you want when building a partial SD that sets only some
 * components.)
 */
void peios_sd_builder_dacl(peios_sd_builder *b, const void *acl, size_t len);
void peios_sd_builder_dacl_null(peios_sd_builder *b);
void peios_sd_builder_sacl(peios_sd_builder *b, const void *acl, size_t len);

const void *peios_sd_builder_bytes(peios_sd_builder *b, size_t *len_out);
ssize_t	    peios_sd_builder_finish(peios_sd_builder *b, void *buf, size_t cap);
int	    peios_sd_builder_error(const peios_sd_builder *b);

/* ====================================================================== */
/* Parsing — zero-copy views                                              */
/* ====================================================================== */

/*
 * Views are caller-allocated (typically on the stack) and borrow the buffer
 * passed to the parse call. The storage below is opaque — do not read its
 * fields; it is sized for stack allocation with headroom for the
 * implementation. Every accessor that yields a SID/ACL/blob hands back a
 * pointer *into the original buffer*, so that buffer must outlive the view.
 */
typedef struct peios_sd_view	    { uint64_t _opaque[8]; } peios_sd_view;
typedef struct peios_acl_view	    { uint64_t _opaque[4]; } peios_acl_view;
typedef struct peios_ace_view	    { uint64_t _opaque[4]; } peios_ace_view;
typedef struct peios_sid_array_view { uint64_t _opaque[4]; } peios_sid_array_view;

/* Validate a self-relative SD and populate @out. Returns 0, or -1 (EINVAL). */
int	 peios_sd_parse(const void *sd, size_t len, peios_sd_view *out);
uint16_t peios_sd_view_control(const peios_sd_view *v);
/* Component accessors: 0 with @sid and @len set on success; -1 if the component
 * is absent (for the DACL/SACL, -1 also distinguishes a NULL DACL). */
int peios_sd_view_owner(const peios_sd_view *v, const void **sid, size_t *len);
int peios_sd_view_group(const peios_sd_view *v, const void **sid, size_t *len);
int peios_sd_view_dacl(const peios_sd_view *v, peios_acl_view *out);
int peios_sd_view_sacl(const peios_sd_view *v, peios_acl_view *out);

/* Parse a bare ACL (e.g. a token default DACL) directly. Returns 0 / -1. */
int	 peios_acl_parse(const void *acl, size_t len, peios_acl_view *out);
unsigned peios_acl_view_count(const peios_acl_view *a);
/* Populate @out for ACE @i (0-based, in stored order). Returns 0 / -1 (ERANGE). */
int	 peios_acl_view_ace(const peios_acl_view *a, unsigned i, peios_ace_view *out);

uint8_t	 peios_ace_view_type(const peios_ace_view *e);
uint8_t	 peios_ace_view_flags(const peios_ace_view *e);
uint32_t peios_ace_view_mask(const peios_ace_view *e);
int	 peios_ace_view_sid(const peios_ace_view *e, const void **sid, size_t *len);
/* Object-ACE GUID(s); 0 with *guid16 set, -1 if not present / not an object ACE. */
int	 peios_ace_view_object_type(const peios_ace_view *e, const uint8_t **guid16);
int	 peios_ace_view_inherited_object_type(const peios_ace_view *e,
					      const uint8_t **guid16);
/* Trailing application data of callback / resource-attribute ACEs. */
int	 peios_ace_view_app_data(const peios_ace_view *e, const void **data,
				 size_t *len);

/*
 * SID-and-attributes arrays — the [count][sid_len][sid][attrs]… blobs returned
 * by the token GROUPS / RESTRICTED_SIDS / DEVICE_GROUPS / CAPABILITIES classes.
 */
int	 peios_sid_array_parse(const void *blob, size_t len,
			       peios_sid_array_view *out);
unsigned peios_sid_array_count(const peios_sid_array_view *a);
int	 peios_sid_array_get(const peios_sid_array_view *a, unsigned i,
			     const void **sid, size_t *len, uint32_t *attrs);

#ifdef __cplusplus
}
#endif

#endif /* PEIOS_SECURITY_H */
