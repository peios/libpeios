/* SPDX-License-Identifier: MIT */
/*
 * <peios/registry.h> — LCS, the Peios registry (Layered Configuration Subsystem).
 *
 * LCS is Peios's kernel-mediated configuration store, modelled on the Windows
 * registry: a hierarchy of keys (immutable GUID identity, each secured by a KACS
 * security descriptor) holding typed values, with every write tagged by a
 * precedence-ordered layer so the effective view resolves to the highest-
 * precedence entry. This header is the registry *client* surface: open keys,
 * read/write values, enumerate, watch, and run transactions.
 *
 * It does not cover the registry *source* (storage backend) side — REG_SRC_REGISTER
 * and the RSI framed protocol — which is a separate concern (a future librsi). A
 * client speaks only the syscalls and key/transaction-fd ioctls declared here.
 *
 * Three syscalls create fds (peios_reg_open_key, peios_reg_create_key,
 * peios_reg_begin_transaction); the rest are ioctls on a key fd or transaction fd,
 * each gated on the access right granted when the key was opened. Errors follow the
 * usual Linux convention (-1 + errno); the buffer-returning queries use the
 * getxattr/ERANGE convention. Wire constants — value types (REG_SZ … REG_QWORD),
 * key access rights (KEY_*), open/create flags, transaction states (REG_TXN_*),
 * watch filters (REG_NOTIFY_*), and security-info bits — come from <pkm/lcs.h>.
 */
#ifndef PEIOS_REGISTRY_H
#define PEIOS_REGISTRY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>		/* ssize_t */

#include <pkm/lcs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ====================================================================== */
/* Key open / create                                                      */
/* ====================================================================== */

/*
 * peios_reg_open_key - open an existing registry key.
 * @parent_fd:      a key fd to resolve @path against, or < 0 for an absolute path.
 * @path:           NUL-terminated registry path.
 * @desired_access: requested KEY_* rights, checked against the key's SD.
 * @flags:          REG_OPEN_LINK to open a symlink key itself (else it is followed).
 *
 * Returns a key fd whose granted access mask is fixed for its lifetime, or -1 with
 * errno: ENOENT, EACCES, EINVAL, ELOOP, ENAMETOOLONG, ETIMEDOUT, EIO, ENOMEM.
 */
int peios_reg_open_key(int parent_fd, const char *path, uint32_t desired_access,
		       uint32_t flags);

/*
 * peios_reg_create_key - open an existing key or create a new one.
 * @parent_fd:       a key fd to resolve @path against, or < 0 for an absolute path.
 * @path:            NUL-terminated registry path.
 * @desired_access:  requested KEY_* rights.
 * @flags:           REG_OPTION_VOLATILE and/or REG_OPTION_CREATE_LINK.
 * @layer:           target layer name (NUL-terminated), or NULL for the base layer.
 * @txn_fd:          a transaction fd to enlist in, or -1 to auto-commit.
 * @disposition_out: may be NULL; else receives REG_CREATED_NEW or
 *                   REG_OPENED_EXISTING.
 *
 * Returns a key fd, or -1 with errno: ENOENT, EACCES, ENOSPC, EINVAL, EPERM
 * (privileged symlink creation), ENAMETOOLONG, ETIMEDOUT, EIO.
 */
int peios_reg_create_key(int parent_fd, const char *path, uint32_t desired_access,
			 uint32_t flags, const char *layer, int txn_fd,
			 uint32_t *disposition_out);

/* ====================================================================== */
/* Values                                                                 */
/* ====================================================================== */

/*
 * Values are named (length-counted; an empty name is the key's default value),
 * typed (REG_*), and written into a layer. A base-layer target is layer == NULL
 * with layer_len == 0 (a non-NULL pointer with a zero length is rejected EINVAL).
 *
 * The buffer-returning reads (query_value, query_values_batch, enum_value) fill the
 * caller's buffer(s) and return 0 with the actual length(s) reported; if a buffer
 * is too small they return -1/ERANGE with the *required* length in the matching
 * *_len field (so a zero-capacity buffer probes the size). For a two-buffer read,
 * ERANGE is returned if either buffer is too small and both required lengths report.
 * A NULL output buffer is valid only with zero capacity; NULL with nonzero capacity
 * is EINVAL.
 */

/*
 * Descriptor for peios_reg_query_value: data and layer-name buffers (in) plus the
 * resolved value's metadata (out). A NULL buffer with zero capacity probes its size.
 */
struct peios_reg_value {
	uint64_t	sequence;	/* out: effective entry's sequence number */
	void	       *data;		/* in:  buffer for the value data (NULL to probe) */
	void	       *layer;		/* in:  buffer for the layer name (NULL to probe/skip) */
	uint32_t	type;		/* out: value type (REG_*) */
	uint32_t	data_cap;	/* in:  data capacity */
	uint32_t	data_len;	/* out: actual / required data length */
	uint32_t	layer_cap;	/* in:  layer capacity */
	uint32_t	layer_len;	/* out: actual / required layer-name length */
};

/*
 * peios_reg_query_value - read the effective value @name on @key_fd.
 * @name/@name_len: length-counted value name (name_len 0 = default value).
 * @txn_fd:         transaction to read within, or -1 for none.
 * @v:              in/out descriptor (see struct peios_reg_value).
 *
 * Returns 0, or -1 with errno: ENOENT (no effective value, or a tombstone), ERANGE,
 * EACCES, EINVAL.
 */
int peios_reg_query_value(int key_fd, const void *name, uint32_t name_len, int txn_fd,
			  struct peios_reg_value *v);

/*
 * peios_reg_set_value - write the value @name in a specific layer.
 * @type:         a REG_* type, or REG_TOMBSTONE for a per-value tombstone.
 * @layer/@len:   target layer name (NULL/0 = base layer).
 * @txn_fd:       transaction, or -1 to auto-commit.
 * @expected_seq: compare-and-swap guard — 0 disables it; otherwise the write
 *                applies only if the current sequence matches, else EAGAIN.
 *
 * Returns 0, or -1 with errno: EINVAL, EAGAIN, ENOSPC, ENAMETOOLONG, EPERM, EACCES.
 */
int peios_reg_set_value(int key_fd, const void *name, uint32_t name_len, uint32_t type,
			const void *data, uint32_t data_len, const void *layer,
			uint32_t layer_len, int txn_fd, uint64_t expected_seq);

/*
 * peios_reg_delete_value - remove a layer's entry for the value @name (NULL/0 layer
 * = base). Idempotent; lower layers re-emerge. @txn_fd, or -1 to auto-commit.
 * Returns 0, or -1 with errno.
 */
int peios_reg_delete_value(int key_fd, const void *name, uint32_t name_len,
			   const void *layer, uint32_t layer_len, int txn_fd);

/*
 * peios_reg_blanket_tombstone - set (@set != 0) or clear (@set == 0) a blanket
 * tombstone on a layer, masking all lower-precedence values of this key on that
 * layer at once. @layer/@len name the layer (NULL/0 = base). @txn_fd, or -1.
 * Returns 0, or -1 with errno (EINVAL if @set is not 0/1, EACCES, …).
 */
int peios_reg_blanket_tombstone(int key_fd, const void *layer, uint32_t layer_len,
				int set, int txn_fd);

/*
 * peios_reg_query_values_batch - read every effective value of @key_fd into @buf.
 * @len_out:   may be NULL; else receives bytes written (or required size on ERANGE).
 * @count_out: may be NULL; else receives the number of records.
 *
 * Each record is packed little-endian as
 *   [name_len: u32][name][type: u32][data_len: u32][data]
 * back to back, @count records. Returns 0, or -1 with errno (ERANGE if @cap small).
 */
int peios_reg_query_values_batch(int key_fd, int txn_fd, void *buf, uint32_t cap,
				 uint32_t *len_out, uint32_t *count_out);

/*
 * Descriptor for peios_reg_enum_value: name and data buffers (in) plus the value at
 * the requested index (out). A NULL buffer with zero capacity probes its size.
 */
struct peios_reg_enum_value {
	void	       *name;		/* in:  buffer for the value name (NULL to probe) */
	void	       *data;		/* in:  buffer for the value data (NULL to probe) */
	uint32_t	type;		/* out: value type (REG_*) */
	uint32_t	name_cap;	/* in:  name capacity */
	uint32_t	name_len;	/* out: actual / required name length */
	uint32_t	data_cap;	/* in:  data capacity */
	uint32_t	data_len;	/* out: actual / required data length */
};

/*
 * peios_reg_enum_value - read the effective value at position @index (dense over the
 * key's tombstone-resolved values; walk from 0 until ENOENT). @txn_fd, or -1.
 * Returns 0, or -1 with errno (ENOENT past the end, ERANGE, …).
 */
int peios_reg_enum_value(int key_fd, uint32_t index, int txn_fd,
			 struct peios_reg_enum_value *v);

/* ====================================================================== */
/* Subkeys, metadata, watches                                             */
/* ====================================================================== */

/*
 * Descriptor for peios_reg_enum_subkey: a name buffer (in) plus the child key's
 * metadata (out). A NULL name buffer with zero capacity probes the name length;
 * NULL with nonzero capacity is EINVAL.
 */
struct peios_reg_subkey {
	void	       *name;		/* in:  buffer for the child's name (NULL to probe) */
	uint64_t	last_write_time;/* out: ns since the Unix epoch */
	uint32_t	name_cap;	/* in:  name capacity */
	uint32_t	name_len;	/* out: actual / required name length */
	uint32_t	subkey_count;	/* out: the child's subkey count */
	uint32_t	value_count;	/* out: the child's value count */
};

/*
 * peios_reg_enum_subkey - read the child key at @index (dense over visible children;
 * walk from 0 until ENOENT). No per-child access check. @txn_fd, or -1. A too-small
 * name buffer returns ERANGE with the required name_len. Returns 0, or -1 with errno.
 */
int peios_reg_enum_subkey(int key_fd, uint32_t index, int txn_fd,
			  struct peios_reg_subkey *v);

/*
 * Descriptor for peios_reg_query_key_info: a name buffer (in) plus the key's
 * metadata (out). The kernel reports metadata only once the name fits, so size the
 * name buffer first (a zero-capacity probe returns ERANGE with the required name_len).
 * A NULL name buffer with nonzero capacity is EINVAL.
 */
struct peios_reg_key_info {
	void	       *name;		/* in:  buffer for the key's leaf name (NULL to probe) */
	uint64_t	last_write_time;	/* out */
	uint64_t	hive_generation;	/* out: per-hive change epoch */
	uint32_t	name_cap;		/* in:  name capacity */
	uint32_t	name_len;		/* out: actual / required name length */
	uint32_t	subkey_count;		/* out */
	uint32_t	value_count;		/* out */
	uint32_t	max_subkey_name_len;	/* out */
	uint32_t	max_value_name_len;	/* out */
	uint32_t	max_value_data_size;	/* out */
	uint32_t	sd_size;		/* out: security-descriptor size */
	uint8_t		volatile_key;		/* out: 1 if volatile */
	uint8_t		symlink;		/* out: 1 if a symlink */
};

/*
 * peios_reg_query_key_info - read the key's name and metadata (READ_CONTROL). A
 * too-small (or zero-capacity) name buffer returns ERANGE with the required
 * name_len; size it and call again to obtain the metadata. Returns 0, or -1+errno.
 */
int peios_reg_query_key_info(int key_fd, struct peios_reg_key_info *v);

/*
 * peios_reg_delete_key - remove this key's path entry in a layer (NULL/0 = base;
 * lower entries re-emerge). Cannot delete a hive root (EINVAL) or a key with visible
 * children (ENOTEMPTY). DELETE access. @txn_fd, or -1. Returns 0, or -1 with errno.
 */
int peios_reg_delete_key(int key_fd, const void *layer, uint32_t layer_len, int txn_fd);

/*
 * peios_reg_hide_key - create a HIDDEN path entry masking this key in a layer
 * (NULL/0 = base); removing the layer makes the key reappear. Cannot hide a hive
 * root (EINVAL). DELETE access. @txn_fd, or -1. Returns 0, or -1 with errno.
 */
int peios_reg_hide_key(int key_fd, const void *layer, uint32_t layer_len, int txn_fd);

/*
 * peios_reg_notify - arm (or, with @filter == 0, disarm) change watches on @key_fd
 * (KEY_NOTIFY). @filter is a mask of REG_NOTIFY_VALUE/SUBKEY/SD (REG_NOTIFY_ALL for
 * all); @subtree (0/1) extends to descendants. Once armed the fd is pollable
 * (EPOLLIN = events pending) and read() returns the records. Returns 0, or -1 with
 * errno (ENOENT on an orphaned key, EINVAL, EACCES).
 */
int peios_reg_notify(int key_fd, uint32_t filter, int subtree);

/*
 * peios_reg_flush - force the source to persist this key's hive's pending writes
 * (KEY_SET_VALUE); returns once persistence is confirmed. Returns 0, or -1+errno.
 */
int peios_reg_flush(int key_fd);

/* ====================================================================== */
/* Security descriptors                                                   */
/* ====================================================================== */

/*
 * peios_reg_get_security - read the @security_info components of the key's SD into
 * @sd (KACS binary format), writing the length to *@sd_len_out (may be NULL). A
 * too-small buffer returns -1/ERANGE with the required size there (a zero @cap
 * probes). A NULL @sd with nonzero @cap is EINVAL. Owner/group/DACL need READ_CONTROL; the SACL needs
 * ACCESS_SYSTEM_SECURITY. Returns 0, or -1 with errno.
 */
int peios_reg_get_security(int key_fd, uint32_t security_info, void *sd, uint32_t cap,
			   uint32_t *sd_len_out);

/*
 * peios_reg_set_security - apply the @security_info components of @sd (a KACS binary
 * security descriptor) to the key's SD, merging with the rest; the kernel parses and
 * validates it. Modifying the DACL needs WRITE_DAC, the owner WRITE_OWNER, the SACL
 * ACCESS_SYSTEM_SECURITY. @txn_fd gives atomicity (not layer qualification), or -1
 * to apply immediately. SD changes affect only future opens. Returns 0, or -1+errno.
 */
int peios_reg_set_security(int key_fd, uint32_t security_info, const void *sd,
			   uint32_t sd_len, int txn_fd);

/* ====================================================================== */
/* Backup / restore                                                       */
/* ====================================================================== */

/*
 * peios_reg_backup - export the key and its entire subtree to @output_fd
 * (SeBackupPrivilege). Takes a read-only snapshot; no per-key access check. Returns
 * 0, or -1 with errno: EPERM/EACCES, EBADF (output_fd not writable), ENOENT
 * (orphaned key), ENOTSUP, EBUSY.
 */
int peios_reg_backup(int key_fd, int output_fd);

/*
 * peios_reg_restore - replace the key and its entire subtree from @input_fd
 * (SeRestorePrivilege), applied in one transaction. Returns 0, or -1 with errno:
 * EPERM/EACCES, EBADF (input_fd not readable), EINVAL (malformed stream), EEXIST
 * (GUID collision), EOVERFLOW.
 */
int peios_reg_restore(int key_fd, int input_fd);

/* ====================================================================== */
/* Transactions                                                           */
/* ====================================================================== */

/*
 * peios_reg_begin_transaction - start a new registry transaction.
 *
 * Returns a transaction fd (initially unbound; binds to a source on first use), or
 * -1 with errno (ENOMEM). Pass the fd as the txn_fd argument of key creates and the
 * mutating value/key operations to enlist them, then peios_reg_commit() to apply
 * atomically. Closing the fd without committing aborts the transaction.
 */
int peios_reg_begin_transaction(void);

/*
 * peios_reg_commit - atomically commit everything enlisted in @txn_fd.
 *
 * Returns 0 on commit (the fd is then terminal — close it), or -1 with errno:
 * EINVAL (already committed / never bound), EBUSY (write-lock contention; the
 * transaction stays active, retry), EIO (source failure; stays active), ETIMEDOUT.
 */
int peios_reg_commit(int txn_fd);

/*
 * peios_reg_txn_status - read the state of a transaction fd.
 * @state_out:          may be NULL; else receives the REG_TXN_* state.
 * @terminal_errno_out: may be NULL; else receives the errno that ended the
 *                      transaction (0 while active or after a clean commit).
 *
 * Returns 0, or -1 with errno.
 */
int peios_reg_txn_status(int txn_fd, uint32_t *state_out, int *terminal_errno_out);

#ifdef __cplusplus
}
#endif

#endif /* PEIOS_REGISTRY_H */
