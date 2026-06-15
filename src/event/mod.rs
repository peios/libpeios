//! `<peios/event.h>` — KMES events.
//!
//! KMES is Peios's sole event path: the kernel stamps each event with trusted
//! metadata and writes it into a per-CPU lock-free ring buffer. This module is
//! built in slices — **emit** (the producer side, [`emit`]) first; the consumer
//! side (`attach` + the ring-buffer reader) lands next. Payloads are MessagePack
//! (`crate::msgpack`).

pub mod consume;
pub mod emit;
