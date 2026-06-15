/* SPDX-License-Identifier: MIT */
/*
 * <peios.h> — libpeios umbrella header.
 *
 * Pulls in the entire libpeios public API. Include this for convenience, or
 * include the individual concept headers for a tighter surface.
 *
 * KACS (access control): <peios/security.h>, <peios/token.h>,
 *   <peios/access.h>, <peios/file.h>, <peios/process.h>.
 * KMES (events): <peios/msgpack.h>, <peios/event.h>.
 * LCS (registry): <peios/registry.h>.
 */
#ifndef PEIOS_H
#define PEIOS_H

#include <peios/security.h>
#include <peios/token.h>
#include <peios/access.h>
#include <peios/file.h>
#include <peios/process.h>
#include <peios/msgpack.h>
#include <peios/event.h>
#include <peios/registry.h>

#endif /* PEIOS_H */
