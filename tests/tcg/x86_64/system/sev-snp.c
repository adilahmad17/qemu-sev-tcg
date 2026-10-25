/*
 * Emulated SEV-SNP guest test: PVALIDATE, RMPADJUST, page-state changes,
 * the CPUID and secrets pages, the "page not validated" #VC and AP creation.
 *
 * Copyright (C) 2026 The ASTERISC Research Lab
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define SEV_SNP_TEST
#include "sev-es.c"
