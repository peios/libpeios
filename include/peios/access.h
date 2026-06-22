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
	const void     *audit_context;	/* opaque object id for audit events */
	size_t		audit_context_len;
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

#ifdef __cplusplus
}
#endif

#endif /* PEIOS_ACCESS_H */
