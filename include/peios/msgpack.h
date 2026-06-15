/* SPDX-License-Identifier: MIT */
/*
 * <peios/msgpack.h> — an in-house MessagePack codec.
 *
 * KMES event payloads (<peios/event.h>) are MessagePack; the kernel only
 * structurally validates them on emit, so userspace owns the encode/decode.
 * This codec is that path: a heap-backed writer (encoder), a stack-allocatable
 * reader (decoder cursor), and a validator whose acceptance is matched to the
 * kernel's emit-time check, so a payload this codec produces and validates is
 * accepted by the event emit calls.
 *
 * Conventions: integers are written in their smallest MessagePack form; `str`
 * values must be valid UTF-8 (use `bin` for arbitrary bytes); a valid payload is
 * exactly one top-level value, and an empty buffer is not valid. The writer is
 * sticky-error like the <peios/security.h> builders: setters cannot fail
 * individually; the first error latches and surfaces at peios_mp_writer_bytes()
 * and peios_mp_writer_error().
 */
#ifndef PEIOS_MSGPACK_H
#define PEIOS_MSGPACK_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>		/* ssize_t */

#ifdef __cplusplus
extern "C" {
#endif

/* ====================================================================== */
/* Writer (encoder)                                                       */
/* ====================================================================== */

typedef struct peios_mp_writer peios_mp_writer;

peios_mp_writer *peios_mp_writer_new(void);
void		 peios_mp_writer_free(peios_mp_writer *w);
void		 peios_mp_writer_reset(peios_mp_writer *w);

void peios_mp_write_nil(peios_mp_writer *w);
void peios_mp_write_bool(peios_mp_writer *w, bool v);
void peios_mp_write_int(peios_mp_writer *w, int64_t v);
void peios_mp_write_uint(peios_mp_writer *w, uint64_t v);
void peios_mp_write_float(peios_mp_writer *w, double v);
void peios_mp_write_str(peios_mp_writer *w, const char *s, size_t len);	/* UTF-8 */
void peios_mp_write_bin(peios_mp_writer *w, const void *b, size_t len);

/* Container headers: write the header, then exactly @count values (a map needs
 * @count key/value PAIRS, i.e. 2 * @count values). An under- or over-filled
 * container is reported at peios_mp_writer_bytes(). */
void peios_mp_write_array(peios_mp_writer *w, uint32_t count);
void peios_mp_write_map(peios_mp_writer *w, uint32_t count);

void peios_mp_write_ext(peios_mp_writer *w, int8_t ext_type, const void *b, size_t len);

/* Append pre-encoded MessagePack bytes verbatim (the escape hatch). The whole
 * buffer is still structurally validated at peios_mp_writer_bytes(). */
void peios_mp_write_raw(peios_mp_writer *w, const void *b, size_t len);

/*
 * Borrow the encoded buffer (valid until the next mutating call on @w) via @out
 * and return its length, after confirming it is exactly one well-formed
 * top-level value. Returns -1 with errno (EINVAL on a latched error or malformed
 * structure, ENOMEM on a prior allocation failure).
 */
ssize_t peios_mp_writer_bytes(peios_mp_writer *w, const void **out);

/* The latched errno, or 0 if healthy. */
int peios_mp_writer_error(const peios_mp_writer *w);

/* ====================================================================== */
/* Reader (decoder)                                                       */
/* ====================================================================== */

/* The value kind reported by peios_mp_peek(). Integers (signed and unsigned, all
 * widths) report as PEIOS_MP_INT; read them with peios_mp_read_int/_uint. */
enum peios_mp_type {
	PEIOS_MP_NIL	= 0,
	PEIOS_MP_BOOL	= 1,
	PEIOS_MP_INT	= 2,
	PEIOS_MP_FLOAT	= 3,
	PEIOS_MP_STR	= 4,
	PEIOS_MP_BIN	= 5,
	PEIOS_MP_ARRAY	= 6,
	PEIOS_MP_MAP	= 7,
	PEIOS_MP_EXT	= 8,
};

/* A decode cursor over a borrowed buffer; stack-allocatable. Opaque storage —
 * initialize with peios_mp_reader_init() before use, and do not inspect fields.
 * Borrowed str/bin/ext pointers point into the original buffer and are valid for
 * as long as it is. */
struct peios_mp_reader {
	uint64_t _opaque[4];
};

void   peios_mp_reader_init(struct peios_mp_reader *r, const void *buf, size_t len);
size_t peios_mp_reader_remaining(const struct peios_mp_reader *r);

/* The peios_mp_type of the next value without consuming it, or -1 at
 * end-of-input or on an invalid lead byte. */
int peios_mp_peek(const struct peios_mp_reader *r);

/* Each read consumes one value on success (0 / a length) and leaves the cursor
 * untouched on a type mismatch or truncation (-1 with errno == EINVAL). */
int peios_mp_read_nil(struct peios_mp_reader *r);
int peios_mp_read_bool(struct peios_mp_reader *r, bool *out);
int peios_mp_read_int(struct peios_mp_reader *r, int64_t *out);
int peios_mp_read_uint(struct peios_mp_reader *r, uint64_t *out);
int peios_mp_read_float(struct peios_mp_reader *r, double *out);

/* Borrow str/bin bytes (a pointer into the reader's buffer) and return the
 * length, or -1. Strings are not NUL-terminated — use the length. */
ssize_t peios_mp_read_str(struct peios_mp_reader *r, const char **out);
ssize_t peios_mp_read_bin(struct peios_mp_reader *r, const void **out);

/* Consume a container header. peios_mp_read_array returns the element count;
 * peios_mp_read_map returns the key/value PAIR count (read 2 * count values).
 * The caller then reads that many values. -1 on a type mismatch. */
ssize_t peios_mp_read_array(struct peios_mp_reader *r);
ssize_t peios_mp_read_map(struct peios_mp_reader *r);

/* Borrow an extension value's bytes, reporting its signed type id via @type_out;
 * returns the data length, or -1. */
ssize_t peios_mp_read_ext(struct peios_mp_reader *r, int8_t *type_out, const void **out);

/* Skip exactly one complete value (descending into nested containers). 0 on
 * success, -1 with errno on malformed input. */
int peios_mp_skip(struct peios_mp_reader *r);

/* ====================================================================== */
/* Validator                                                              */
/* ====================================================================== */

/*
 * Confirm @buf/@len is exactly one well-formed MessagePack value: UTF-8 strings,
 * nesting bounded by @max_depth, no trailing bytes, non-empty. Matches the
 * kernel's emit-time check, so a 0 return means the event emit calls will accept
 * the payload (at this depth bound). Returns 0 if valid, -1 with errno == EINVAL
 * otherwise. Pass KMES_CONFIG_MAX_NESTING_DEPTH_DEFAULT (32) for the default
 * emit limit; the top-level value is depth 1.
 */
int peios_mp_validate(const void *buf, size_t len, uint32_t max_depth);

#ifdef __cplusplus
}
#endif

#endif /* PEIOS_MSGPACK_H */
