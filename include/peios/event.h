/* SPDX-License-Identifier: MIT */
/*
 * <peios/event.h> — KMES events.
 *
 * KMES is Peios's sole event path. The kernel stamps each event with trusted
 * metadata (timestamp, per-CPU sequence, CPU id, identity GUIDs) and writes it
 * into a per-CPU lock-free ring buffer; there is no other way to emit or observe
 * events. Producers emit here; consumers attach to and drain the ring buffers
 * through this header. Each event payload is a single MessagePack
 * value — build and parse them with <peios/msgpack.h>.
 *
 * Emission requires SeAuditPrivilege. The kernel validates the payload (it must
 * be one well-formed MessagePack value within the configured size and nesting
 * limits) and stamps origin_class = userspace. Wire constants
 * (KMES_BATCH_MAX_ENTRIES, KMES_CONFIG_*) come from <pkm/kmes.h>.
 */
#ifndef PEIOS_EVENT_H
#define PEIOS_EVENT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>		/* ssize_t */

#include <pkm/kmes.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ====================================================================== */
/* Emit (producer side)                                                   */
/* ====================================================================== */

/*
 * peios_event_emit - emit a single event.
 * @event_type:     length-counted UTF-8 event kind (e.g. "my.app.login"); not
 *                  NUL-terminated.
 * @event_type_len: length of @event_type in bytes (must be non-zero).
 * @payload:        @payload_len bytes of MessagePack (one well-formed value).
 *
 * Returns 0, or -1 with errno: EPERM (no SeAuditPrivilege), EINVAL (zero-length
 * type or malformed payload), ENOSPC (exceeds the size caps), EAGAIN
 * (rate-limited), EFAULT (bad pointer).
 */
int peios_event_emit(const char *event_type, uint16_t event_type_len,
		     const void *payload, uint32_t payload_len);

/* One entry of a batch emit. */
struct peios_event_entry {
	const char     *event_type;	/* length-counted UTF-8; not NUL-terminated */
	uint16_t	event_type_len;
	const void     *payload;	/* MessagePack bytes */
	uint32_t	payload_len;
};

/*
 * peios_event_emit_batch - emit several events in one call, amortizing the
 * per-call overhead (a single timestamp / identity capture / wake covers all).
 * @entries:     array of @count entries.
 * @count:       in [1, KMES_BATCH_MAX_ENTRIES].
 * @emitted_out: may be NULL; otherwise receives the number actually emitted.
 *
 * Returns 0 if all @count were emitted, or -1 with errno from the first entry
 * that failed (with *emitted_out set to how many preceded it). Rate-limiting is
 * all-or-nothing: EAGAIN emits none.
 */
int peios_event_emit_batch(const struct peios_event_entry *entries,
			   uint32_t count, uint32_t *emitted_out);

/* ====================================================================== */
/* Consume (consumer side)                                                */
/* ====================================================================== */

/*
 * A parsed event. The kernel-stamped header is copied by value; @event_type and
 * @payload point into the ring mapping and are valid only until the next read
 * advance (and only while the slot has not been overwritten — copy out what you
 * need before continuing). @payload is a MessagePack value (see <peios/msgpack.h>).
 * @origin_class: 0 = userspace, 1 = KMES, 2 = KACS, 3 = LCS.
 */
struct peios_event {
	uint64_t	timestamp;	/* ns since the Unix epoch (CLOCK_REALTIME) */
	uint64_t	sequence;	/* per-CPU, per-boot monotonic (gap = lost events) */
	uint16_t	cpu_id;
	uint8_t		origin_class;
	uint8_t		effective_token_guid[16];
	uint8_t		true_token_guid[16];
	uint8_t		process_guid[16];
	const char     *event_type;	/* not NUL-terminated; use event_type_len */
	uint16_t	event_type_len;
	const void     *payload;
	uint32_t	payload_len;
};

/*
 * Attach to CPU @cpu_id's ring buffer: returns a fd and writes the data-region
 * capacity to *@capacity_out. Discover the CPU count by counting up from 0 until
 * this returns -1 with errno == EINVAL. Requires SeSecurityPrivilege (EPERM
 * otherwise). The low-level path then mmaps the fd via peios_event_ring_map().
 */
int peios_event_attach(uint32_t cpu_id, uint64_t *capacity_out);

/* ---- high-level reader ----------------------------------------------- */

/*
 * The reader owns the attach + mmap and hides the lock-free drain: memory
 * barriers, lapping recovery, sequence-gap (lost-event) accounting, buffer
 * resize/generation handling, and the futex wait. Just loop next()/wait().
 */
typedef struct peios_event_reader peios_event_reader;

/* Attach to @cpu_id and map its ring, ready to drain. NULL with errno on failure. */
peios_event_reader *peios_event_reader_open(uint32_t cpu_id);
void		    peios_event_reader_close(peios_event_reader *r);

/*
 * Fetch the next event into @out. Returns 1 (event filled), 0 (none available —
 * consider peios_event_reader_wait), or -1 with errno. The @out pointers are
 * valid only until the next call. @out must be non-NULL.
 */
int peios_event_reader_next(peios_event_reader *r, struct peios_event *out);

/*
 * Block until events are available or @timeout_ms elapses (negative = forever).
 * Returns 1 (call next), 0 (timeout / interrupted), or -1 on error.
 */
int peios_event_reader_wait(peios_event_reader *r, int timeout_ms);

/* The cumulative count of lost events (overwritten or dropped), from sequence gaps. */
uint64_t peios_event_reader_lost(const peios_event_reader *r);

/* ---- low-level ring (drive your own loop) ---------------------------- */

/*
 * A mapped ring buffer for callers that drive the drain themselves. The accessors
 * apply the correct memory barriers; the caller owns the read position and the
 * empty (write_pos) / lapping (tail_pos) / generation checks. Positions are
 * free-running byte counters; an event lives at (read_pos & (capacity - 1)).
 */
struct peios_event_ring {
	uint64_t _opaque[4];
};

/* Map (and validate) a ring fd from peios_event_attach. @ring must be zeroed or
 * previously unmapped; remapping an active ring fails with EBUSY. 0, or -1 with
 * errno. */
int  peios_event_ring_map(int fd, uint64_t capacity, struct peios_event_ring *ring);
void peios_event_ring_unmap(struct peios_event_ring *ring);

uint64_t peios_event_ring_capacity(const struct peios_event_ring *ring);
uint64_t peios_event_ring_write_pos(const struct peios_event_ring *ring);	/* acquire */
uint64_t peios_event_ring_tail_pos(const struct peios_event_ring *ring);		/* acquire */
uint64_t peios_event_ring_generation(const struct peios_event_ring *ring);

/* Arm (@set != 0) or clear the advisory wake flag before sleeping. */
void peios_event_ring_set_need_wake(const struct peios_event_ring *ring, int set);

/*
 * Parse the event at @read_pos into @out; returns its byte size (advance read_pos
 * by it), or -1 if the slot is corrupt. The caller must have confirmed read_pos
 * is in [tail_pos, write_pos). @out may be NULL to validate the slot and return
 * the byte size without borrowing event_type/payload pointers.
 */
ssize_t peios_event_ring_event_at(const struct peios_event_ring *ring,
				  uint64_t read_pos, struct peios_event *out);

/* Futex wait until events past @read_pos may be available or @timeout_ms elapses
 * (negative = forever). 1 (drain now), 0 (timeout / interrupted), or -1. */
int peios_event_ring_wait(const struct peios_event_ring *ring,
			  uint64_t read_pos, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* PEIOS_EVENT_H */
