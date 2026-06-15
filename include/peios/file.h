/* SPDX-License-Identifier: MIT */
/*
 * <peios/file.h> — KACS native file objects.
 *
 * peios_file_open() is the NtCreateFile-shaped native open: it carries a
 * desired access mask, a create disposition, create options, and an optional
 * creator security descriptor, and returns an ordinary Linux file fd whose
 * granted access mask is fixed for the fd's lifetime (so it can be delegated by
 * dup / SCM_RIGHTS / exec). The get/set-SD calls read and write a file's
 * security descriptor by path or by fd; the mount-policy calls govern how a
 * superblock without native SD storage is treated.
 *
 * Wire constants (KACS_DISPOSITION_*, KACS_CREATE_OPT_*, KACS_FILE_*,
 * KACS_SECINFO_*, KACS_MOUNT_POLICY_*, KACS_STATUS_*) come from <pkm/file.h>
 * and <pkm/sd.h>. See <peios/security.h> for the library conventions and for
 * building the security descriptors these calls exchange.
 */
#ifndef PEIOS_FILE_H
#define PEIOS_FILE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>		/* ssize_t */

#include <pkm/sd.h>		/* struct kacs_generic_mapping */
#include <pkm/file.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Parameters for peios_file_open(). libpeios marshals these into a
 * struct kacs_open_how (setting its size and zeroing reserved fields).
 */
struct peios_open_params {
	uint32_t	desired_access;	/* KACS_FILE_* | standard | generic (strict-mode) */
	uint32_t	disposition;	/* KACS_DISPOSITION_*  */
	uint32_t	options;	/* KACS_CREATE_OPT_*   */
	uint32_t	flags;		/* AT_SYMLINK_NOFOLLOW | KACS_BACKUP_INTENT | KACS_RESTORE_INTENT */
	const void     *sd;		/* creator SD on create, else NULL */
	size_t		sd_len;
};

/*
 * peios_file_open - native KACS open of @path relative to @dirfd.
 * @status_out: if non-NULL, receives KACS_STATUS_* (opened / created / …).
 * Returns a file fd, or -1 with errno.
 */
int peios_file_open(int dirfd, const char *path,
		    const struct peios_open_params *p, uint32_t *status_out);

/*
 * Read a file's security descriptor. @secinfo selects components
 * (KACS_SECINFO_*); @at_flags accepts AT_SYMLINK_NOFOLLOW. getxattr-style:
 * pass cap == 0 to probe for the size; a too-small non-zero buffer fails with
 * ERANGE and writes nothing — libpeios never yields a truncated SD.
 */
ssize_t peios_file_get_sd(int dirfd, const char *path, uint32_t secinfo,
			  void *buf, size_t cap, uint32_t at_flags);

/* Write the @secinfo components of @sd onto a file; preserves the rest. */
int peios_file_set_sd(int dirfd, const char *path, uint32_t secinfo,
		      const void *sd, size_t len, uint32_t at_flags);

/*
 * fd-targeted SD get/set — operate on the object @fd already refers to. The
 * effective access check depends on the fd type (the cached granted mask for a
 * normal file fd, a live check for an O_PATH / pidfd / token fd); see
 * PSD-004 §11.5.
 */
ssize_t peios_fd_get_sd(int fd, uint32_t secinfo, void *buf, size_t cap);
int	peios_fd_set_sd(int fd, uint32_t secinfo, const void *sd, size_t len);

/*
 * Mount policy for the superblock @fd lives on (SeTcbPrivilege). On get,
 * @out->template_sd points into @tmpl_buf when it is large enough (getxattr-
 * style on that buffer), or is NULL if there is no template.
 */
struct peios_mount_policy {
	uint32_t	policy;		/* KACS_MOUNT_POLICY_* */
	uint32_t	flags;
	uint32_t	generation;
	const void     *template_sd;
	size_t		template_sd_len;
};
int peios_mount_get_policy(int fd, struct peios_mount_policy *out,
			   void *tmpl_buf, size_t tmpl_cap);
int peios_mount_set_policy(int fd, const struct peios_mount_policy *p);

/* The canonical KACS generic mapping for the file object class. */
extern const struct kacs_generic_mapping peios_file_generic_mapping;

#ifdef __cplusplus
}
#endif

#endif /* PEIOS_FILE_H */
