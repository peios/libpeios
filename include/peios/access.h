/* SPDX-License-Identifier: MIT */
/*
 * <peios/access.h> — KACS access checks.
 *
 * peios_access_check() runs the full KACS AccessCheck pipeline for a token
 * against a security descriptor and a desired access mask, reporting whether
 * access is granted and the granted mask. peios_access_check_list() is the
 * object-type-list variant (AccessCheckByTypeResultList). Both are advisory:
 * they evaluate, they do not enforce — enforcement always uses the subject's
 * process security block.
 *
 * libpeios owns the versioned struct kacs_access_check_args (it sets
 * caller_size and zeroes the reserved fields); callers fill the request below.
 * The object-tree / node-result / claim types come from <pkm/access.h>;
 * security descriptors are built via <peios/security.h>.
 */
#ifndef PEIOS_ACCESS_H
#define PEIOS_ACCESS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>		/* ssize_t */

#include <pkm/sd.h>		/* struct kacs_generic_mapping */
#include <pkm/access.h>		/* kacs_object_type_entry, kacs_node_result */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * An access-check request. Only the first block is needed for an ordinary
 * check; everything below the divider is advanced and may be left zero/NULL.
 * For pointer/length pairs, NULL is valid only when the corresponding length
 * or count is zero.
 */
struct peios_access_request {
	int		token_fd;	/* -1 = the caller's effective token */
	const void     *sd;
	size_t		sd_len;
	uint32_t	desired;	/* desired access mask */
	struct kacs_generic_mapping mapping;	/* the object class's mapping */

	/* ---- [adv] ---- */
	const void     *self_sid;	/* PRINCIPAL_SELF substitution; NULL */
	size_t		self_sid_len;
	uint32_t	privilege_intent;	/* backup/restore intent bits */
	const struct kacs_object_type_entry *object_tree;
	uint32_t	object_tree_count;
	const void     *local_claims;	/* @Local claim array */
	size_t		local_claims_len;
	uint32_t	pip_type;	/* 0 = use the subject's PSB */
	uint32_t	pip_trust;
	const void     *audit_context;	/* the guarded object, a PGSS 6.7 map; */
	size_t		audit_context_len;	/* see peios_audit_context_encode() */
};

/* Audit outputs [adv], filled if requested. */
struct peios_access_audit {
	uint32_t	continuous_audit;	/* OR of matching alarm masks */
	int		staging_mismatch;	/* 1 if the staged CAAP result differs */
};

/*
 * Returns 0 if every desired right is granted; -1 with errno == EACCES if any
 * is denied (other errno on error). @granted, if non-NULL, always receives the
 * granted mask (even on denial). @audit, if non-NULL, receives the audit
 * outputs.
 */
int peios_access_check(const struct peios_access_request *req,
		       uint32_t *granted, struct peios_access_audit *audit);

/*
 * AccessCheckByTypeResultList [adv]: @req->object_tree is mandatory; @results
 * receives one entry per node in preorder and @count must equal
 * object_tree_count. Returns 0 / -1.
 */
int peios_access_check_list(const struct peios_access_request *req,
			    struct kacs_node_result *results, uint32_t count);

/* ---- audit context [adv] ---------------------------------------------- */

/*
 * A daemon that guards objects of its own names the object it checked, so the
 * kernel's audit record of the check says what was decided on. The context is
 * one MessagePack map (PGSS 6.7):
 *
 *     {kind: "service", service: {name: "jellyfin"}}
 *
 * The kernel copies it into kacs.audit.access.checked as object.kind and
 * object.<kind>.*, marked fields.attestation.userspace, and fails the check
 * with EINVAL for any other shape. Both access-check calls validate a
 * non-NULL audit_context against the kernel's rules before the syscall, so a
 * malformed one fails there with EINVAL; a non-NULL pointer with a zero
 * length is refused too.
 */

/* Which member of a struct peios_audit_field carries its value. */
enum peios_audit_value_type {
	PEIOS_AUDIT_STR	 = 0,	/* bytes/len: a UTF-8 string, not NUL-terminated */
	PEIOS_AUDIT_UINT = 1,	/* scalar */
	PEIOS_AUDIT_INT	 = 2,	/* scalar, read as a two's-complement int64_t */
	PEIOS_AUDIT_BOOL = 3,	/* scalar: 0 or 1 */
	PEIOS_AUDIT_BIN	 = 4,	/* bytes/len: binary, e.g. a SID or GUID */
};

/* One identifying field of the object, written as object.<kind>.<key>. */
struct peios_audit_field {
	const char     *key;		/* NUL-terminated; one kebab-case segment */
	uint32_t	value_type;	/* enum peios_audit_value_type */
	uint64_t	scalar;
	const void     *bytes;
	size_t		len;
};

/*
 * Encode an audit context naming an object of kind @kind by @count @fields,
 * getxattr-style. @kind and each key are one kebab-case event-name segment,
 * [a-z][a-z0-9]*(-[a-z0-9]+)*; with no fields the context is {kind: @kind}.
 * Fails with EINVAL for a bad kind or key, a key given twice, an unknown
 * value type, a boolean other than 0 or 1, a string that is not UTF-8, or a
 * context longer than KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN bytes. Values
 * are scalars only: an event field is never nil (it is omitted instead).
 */
ssize_t peios_audit_context_encode(const char *kind,
				   const struct peios_audit_field *fields,
				   size_t count, void *buf, size_t cap);

/*
 * Check a context built some other way (e.g. with <peios/msgpack.h>) against
 * the kernel's rules. Returns 0 if the kernel would accept it; -1 with EINVAL
 * otherwise, including for NULL or empty input.
 */
int peios_audit_context_validate(const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PEIOS_ACCESS_H */
