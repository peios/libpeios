/* SPDX-License-Identifier: MIT */
/*
 * <peios/token.h> — KACS access tokens, sessions, and process primary tokens.
 *
 * A token handle is an fd. These calls open or mint tokens, query their
 * contents by information class, adjust privileges and groups, duplicate /
 * restrict / link them, impersonate, and install one as a process's primary
 * token. Logon sessions — the lightweight kernel bookkeeping a token
 * references — live here too.
 *
 * The token-spec builder is the ergonomic path to kacs_create_token: it
 * assembles the 192-byte-header wire format from typed setters so callers never
 * hand-pack offsets. Token information-class query payloads (SID arrays, ACLs)
 * are read with the views in <peios/security.h>.
 *
 * Wire constants (KACS_TOKEN_*, KACS_IMLEVEL_*, KACS_SE_*_PRIVILEGE,
 * KACS_TOKEN_CLASS_*, KACS_LOGON_TYPE_*) and the ioctl arg structs
 * (kacs_priv_entry, kacs_group_entry) come from <pkm/token.h>.
 */
#ifndef PEIOS_TOKEN_H
#define PEIOS_TOKEN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>		/* ssize_t */

#include <pkm/token.h>		/* pulls in <pkm/sd.h> */

#ifdef __cplusplus
extern "C" {
#endif

/* ====================================================================== */
/* Opening and creating tokens (each returns a token fd)                  */
/* ====================================================================== */

/* The calling thread's token. @flags may be KACS_TOKEN_OPEN_REAL (the primary
 * token even while impersonating); @access is the desired handle-right mask. */
int peios_token_open_self(unsigned flags, uint32_t access);

/* The primary token of the process referred to by @pidfd. */
int peios_token_open_process(int pidfd, uint32_t access);

/* Thread @tid's impersonation token if it is impersonating, else the process
 * primary token. */
int peios_token_open_thread(int pidfd, int tid, uint32_t access);

/* The peer-identity token captured at connect() on a connected Unix
 * stream/seqpacket socket. The handle carries fixed QUERY | IMPERSONATE rights. */
int peios_token_open_peer(int conn_fd);

/* Mint a token from a pre-built token-spec buffer (escape hatch; prefer the
 * builder below). Requires SeCreateTokenPrivilege. */
int peios_token_create_raw(const void *spec, size_t len);

/* ---- token-spec builder ---------------------------------------------- */

typedef struct peios_token_builder peios_token_builder;

peios_token_builder *peios_token_builder_new(void);
void		     peios_token_builder_free(peios_token_builder *b);
void		     peios_token_builder_reset(peios_token_builder *b);

/* Core fields. Owner / primary-group / restrict indices follow the wire
 * convention: index 0 = the user SID, 1..N = the Nth added group. Do not add
 * the logon SID yourself — the kernel injects it. */
void peios_token_builder_user(peios_token_builder *b, const void *sid, size_t len);
void peios_token_builder_add_group(peios_token_builder *b, const void *sid,
				   size_t len, uint32_t attrs);
void peios_token_builder_privileges(peios_token_builder *b, uint64_t present,
				    uint64_t enabled);
void peios_token_builder_type(peios_token_builder *b, uint8_t type, uint8_t imp_level);
void peios_token_builder_integrity(peios_token_builder *b, uint32_t rid);
void peios_token_builder_session(peios_token_builder *b, uint64_t session_id);
void peios_token_builder_owner_index(peios_token_builder *b, uint32_t index);
void peios_token_builder_primary_group_index(peios_token_builder *b, uint32_t index);
void peios_token_builder_default_dacl(peios_token_builder *b, const void *acl, size_t len);

/* Additional fields [adv]. */
void peios_token_builder_mandatory_policy(peios_token_builder *b, uint32_t bits);
void peios_token_builder_projected_ids(peios_token_builder *b, uint32_t uid, uint32_t gid);
void peios_token_builder_expiration(peios_token_builder *b, uint64_t when);
void peios_token_builder_source(peios_token_builder *b, const char name[8],
				uint64_t source_id);
void peios_token_builder_audit_policy(peios_token_builder *b, uint32_t bits);
void peios_token_builder_add_restricted_sid(peios_token_builder *b, const void *sid,
					    size_t len, uint32_t attrs);
void peios_token_builder_add_device_group(peios_token_builder *b, const void *sid,
					  size_t len, uint32_t attrs);
void peios_token_builder_confinement(peios_token_builder *b, const void *sid, size_t len);
/* Replace projected supplementary GIDs; pass NULL, 0 to clear. */
void peios_token_builder_supp_gids(peios_token_builder *b, const uint32_t *gids,
				   unsigned count);

/* The four token-spec boolean flags, set together via designated initializers. */
struct peios_token_flags {
	bool	write_restricted;
	bool	user_deny_only;
	bool	isolation_boundary;
	bool	confinement_exempt;
};
void peios_token_builder_flags(peios_token_builder *b, const struct peios_token_flags *f);

/* ---- claims & LCS credentials [adv] ---------------------------------- */

/*
 * A single claim value. Which member carries the value is selected by the
 * owning claim's value_type:
 *   KACS_CLAIM_TYPE_INT64 / _UINT64 / _BOOLEAN -> scalar (BOOLEAN: 0 or 1)
 *   KACS_CLAIM_TYPE_STRING -> bytes/len, a UTF-8 string (transcoded to UTF-16LE)
 *   KACS_CLAIM_TYPE_SID    -> bytes/len, a binary SID
 *   KACS_CLAIM_TYPE_OCTET  -> bytes/len, an opaque blob
 */
struct peios_token_claim_value {
	uint64_t	scalar;
	const void     *bytes;
	size_t		len;
};

/* A claim attribute: a named, typed, multi-valued security attribute. */
struct peios_token_claim {
	const char     *name;		/* UTF-8; transcoded to UTF-16LE on the wire */
	uint16_t	value_type;	/* KACS_CLAIM_TYPE_* */
	uint32_t	flags;		/* KACS_CLAIM_ATTR_* */
	const struct peios_token_claim_value *values;
	unsigned	value_count;
};

/* Append a user / device claim. Each is round-tripped through the kernel's own
 * claim parser before acceptance, so a malformed claim latches EINVAL here. */
void peios_token_builder_add_user_claim(peios_token_builder *b,
					const struct peios_token_claim *claim);
void peios_token_builder_add_device_claim(peios_token_builder *b,
					  const struct peios_token_claim *claim);

/*
 * The LCS registry-credentials extension: the layer scope GUIDs the token may
 * resolve plus the private layer names it owns. Set once (replaces any prior);
 * it is emitted as the final token-spec section.
 */
struct peios_token_lcs_credentials {
	const uint8_t (*scope_guids)[16];	/* array of 16-byte GUIDs, each non-nil & unique */
	unsigned	scope_count;		/* <= KACS_TOKEN_LCS_MAX_SCOPE_GUIDS */
	const char *const *private_layers;	/* UTF-8 names, 1..255 bytes, no '/' or '\\', unique */
	unsigned	private_layer_count;	/* <= KACS_TOKEN_LCS_MAX_PRIVATE_LAYERS */
};
void peios_token_builder_lcs_credentials(peios_token_builder *b,
					 const struct peios_token_lcs_credentials *creds);

/* Serialize, or create the token in one step. _bytes() returns the serialized
 * length and, if @out is non-NULL, a pointer into the builder (valid until
 * reset/free); _create() returns the new token fd. */
ssize_t peios_token_builder_bytes(peios_token_builder *b, const void **out);
int	peios_token_builder_create(peios_token_builder *b);
int	peios_token_builder_error(const peios_token_builder *b);

/* ====================================================================== */
/* Query (token information classes)                                      */
/* ====================================================================== */

/* Generic class read, getxattr-style; @info_class is KACS_TOKEN_CLASS_*. SID-
 * array and ACL classes are parsed with the views in <peios/security.h>. */
ssize_t peios_token_query(int fd, uint32_t info_class, void *buf, size_t cap);

/* The four privilege words of KACS_TOKEN_CLASS_PRIVILEGES. */
struct peios_privilege_set {
	uint64_t present;
	uint64_t enabled;
	uint64_t enabled_by_default;
	uint64_t used;
};

/* User SID, getxattr-style like peios_token_query(): pass sid_buf == NULL with
 * cap == 0 to probe for the required size. */
ssize_t peios_token_user(int fd, void *sid_buf, size_t cap);		/* CLASS_USER */

/* Typed convenience over peios_token_query() for the common scalar classes.
 * Output pointers are mandatory and must be non-NULL. */
int	peios_token_type(int fd, uint32_t *out);			/* CLASS_TYPE */
int	peios_token_session_id(int fd, uint32_t *out);			/* CLASS_SESSION_ID */
int	peios_token_integrity(int fd, uint32_t *level_rid_out);		/* CLASS_INTEGRITY_LEVEL */
int	peios_token_privileges(int fd, struct peios_privilege_set *out);	/* CLASS_PRIVILEGES */

/* ====================================================================== */
/* Adjust / transform                                                     */
/* ====================================================================== */

/* Adjust privileges; @prev_enabled (if non-NULL) receives the prior enabled
 * mask. peios_token_reset_privileges() restores enabled := enabled-by-default. */
int peios_token_adjust_privileges(int fd, const struct kacs_priv_entry *entries,
				  unsigned count, uint64_t *prev_enabled);
int peios_token_reset_privileges(int fd);

/* Adjust groups [adv]; @prev_state (if non-NULL) points at a caller array of
 * KACS_TOKEN_GROUP_MASK_WORDS u64 words receiving the prior enabled bitmask. */
int peios_token_adjust_groups(int fd, const struct kacs_group_entry *entries,
			      unsigned count, uint64_t *prev_state);
int peios_token_reset_groups(int fd);

/* Duplicate this token; returns a new fd. @type is KACS_TOKEN_TYPE_*, @imp_level
 * KACS_IMLEVEL_*. */
int peios_token_duplicate(int fd, uint32_t access, uint8_t type, uint8_t imp_level);

/* Create a restricted (filtered) token; returns a new fd [adv]. */
struct peios_token_restrict {
	uint64_t	   privs_to_delete;
	const uint32_t	  *deny_group_indices;	/* groups demoted to deny-only */
	unsigned	   deny_count;
	const void *const *restrict_sids;	/* added restricting SIDs */
	const size_t	  *restrict_sid_lens;
	unsigned	   restrict_count;
	uint32_t	   flags;		/* KACS_TOKEN_RESTRICT_WRITE_RESTRICTED */
};
int peios_token_restrict(int fd, const struct peios_token_restrict *spec);

/* Install this primary token as the calling process's primary token. */
int peios_token_install(int fd);

/* Impersonate this impersonation token on the calling thread. */
int peios_token_impersonate(int fd);

/* Revert the calling thread to its own identity, undoing any active
 * impersonation — the inverse of peios_token_impersonate(). Takes no token: it
 * clears the thread's impersonation token so access checks run as the thread's
 * real (primary) token again. A no-op (reported as success) if not
 * impersonating. Returns 0, or -1 with errno. */
int peios_token_revert(void);

/* Link an elevated + filtered primary-token pair in @session_id [adv]. */
int peios_token_link(int elevated_fd, int filtered_fd, uint64_t session_id);

/* Open this token's linked token; returns a new fd [adv]. */
int peios_token_get_linked(int fd);

/* Replace the token's default DACL and/or owner / primary-group indices [adv].
 * dacl == NULL leaves the DACL unchanged and ignores len; dacl != NULL with
 * len == 0 clears it; an index of 0xFFFF leaves that index unchanged. */
int peios_token_adjust_default(int fd, const void *dacl, size_t len,
			       uint16_t owner_index, uint16_t group_index);

/* Set the token's session id [adv] (SeTcbPrivilege). */
int peios_token_set_session_id(int fd, uint32_t session_id);

/* ====================================================================== */
/* Logon sessions                                                         */
/* ====================================================================== */

struct peios_session_spec {
	uint8_t		logon_type;	/* KACS_LOGON_TYPE_* */
	const char     *auth_package;	/* UTF-8; may be "" */
	const void     *user_sid;
	size_t		user_sid_len;
};

/* Create a logon session (SeTcbPrivilege); @id_out is mandatory and receives the id. */
int peios_session_create(const struct peios_session_spec *spec, uint64_t *id_out);

/* Destroy a session that has no live tokens (SeTcbPrivilege). */
int peios_session_destroy_empty(uint64_t session_id);

/* The canonical KACS generic mapping for the token object class. */
extern const struct kacs_generic_mapping peios_token_generic_mapping;

#ifdef __cplusplus
}
#endif

#endif /* PEIOS_TOKEN_H */
