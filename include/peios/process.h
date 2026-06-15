/* SPDX-License-Identifier: MIT */
/*
 * <peios/process.h> — Peios process security context.
 *
 * For now this is the home of the process security block (PSB) mitigation
 * controls (the kacs_set_psb syscall). Other process-security surface lands
 * here as it appears.
 *
 * The mitigation bits are the KACS_MIT_* flags from <pkm/psb.h> (KACS_MIT_WXP …
 * KACS_MIT_SML, with KACS_MIT_ALL as the valid-bit mask). KACS_MIT_CFI is a
 * legacy alias that expands to KACS_MIT_CFIF | KACS_MIT_CFIB. See PSD-004 §5.
 */
#ifndef PEIOS_PROCESS_H
#define PEIOS_PROCESS_H

#include <stdint.h>

#include <pkm/psb.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Turn on process mitigation bits (one-way — bits can only be set). @mitigations
 * is a mask of KACS_MIT_* bits (<pkm/psb.h>). @pidfd == -1 targets the calling
 * process; targeting another needs PROCESS_SET_INFORMATION on it plus PIP
 * dominance. Activation-backed: if a requested protection cannot be activated
 * the call fails closed without mutating anything.
 */
int peios_process_set_mitigations(int pidfd, uint32_t mitigations);

#ifdef __cplusplus
}
#endif

#endif /* PEIOS_PROCESS_H */
