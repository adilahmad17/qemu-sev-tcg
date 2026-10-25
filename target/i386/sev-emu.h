/*
 * Emulated AMD SEV-ES guest support for TCG: GHCB layout and protocol
 * constants shared by target/i386/sev.c and target/i386/tcg/system/sev-emu.c
 *
 * Copyright (C) 2026 The ASTERISC Research Lab
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef I386_SEV_EMU_H
#define I386_SEV_EMU_H

#include "qemu/osdep.h"

/*
 * The GHCB page (AMD publication 56421, "SEV-ES Guest-Hypervisor Communication
 * Block Standardization"): the save-area fields at the offsets of the VMSA,
 * the software exit fields, a shared buffer and the protocol trailer.
 */
typedef struct QEMU_PACKED GhcbPage {
    uint8_t  reserved_0[0xcb];
    uint8_t  cpl;                   /* 0x0cb */
    uint8_t  reserved_1[0x74];
    uint64_t xss;                   /* 0x140 */
    uint8_t  reserved_2[0x18];
    uint64_t dr7;                   /* 0x160 */
    uint8_t  reserved_3[0x10];
    uint64_t rip;                   /* 0x178 */
    uint8_t  reserved_4[0x58];
    uint64_t rsp;                   /* 0x1d8 */
    uint8_t  reserved_5[0x18];
    uint64_t rax;                   /* 0x1f8 */
    uint8_t  reserved_6[0x108];
    uint64_t rcx;                   /* 0x308 */
    uint64_t rdx;
    uint64_t rbx;
    uint64_t reserved_7;
    uint64_t rbp;                   /* 0x328 */
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint8_t  reserved_8[0x10];
    uint64_t sw_exit_code;          /* 0x390 */
    uint64_t sw_exit_info_1;        /* 0x398 */
    uint64_t sw_exit_info_2;        /* 0x3a0 */
    uint64_t sw_scratch;            /* 0x3a8 */
    uint8_t  reserved_9[0x38];
    uint64_t xcr0;                  /* 0x3e8 */
    uint8_t  valid_bitmap[16];      /* 0x3f0 */
    uint64_t x87_state_gpa;         /* 0x400 */
    uint8_t  reserved_10[0x3f8];
    uint8_t  shared_buffer[0x7f0];  /* 0x800 */
    uint8_t  reserved_11[0xa];
    uint16_t protocol_version;      /* 0xffa */
    uint32_t ghcb_usage;            /* 0xffc */
} GhcbPage;

QEMU_BUILD_BUG_ON(sizeof(GhcbPage) != 4096);
QEMU_BUILD_BUG_ON(offsetof(GhcbPage, sw_exit_code) != 0x390);
QEMU_BUILD_BUG_ON(offsetof(GhcbPage, shared_buffer) != 0x800);

/* one valid bit per 8-byte field of the save area */
#define GHCB_FIELD_BIT(field)   (offsetof(GhcbPage, field) / 8)

static inline bool ghcb_field_valid(const GhcbPage *ghcb, unsigned bit)
{
    return ghcb->valid_bitmap[bit / 8] & (1 << (bit % 8));
}

static inline void ghcb_field_set_valid(GhcbPage *ghcb, unsigned bit)
{
    ghcb->valid_bitmap[bit / 8] |= 1 << (bit % 8);
}

#define GHCB_SET(ghcb, field, value) do {                       \
        (ghcb)->field = (value);                                \
        ghcb_field_set_valid((ghcb), GHCB_FIELD_BIT(field));    \
    } while (0)

#define GHCB_PROTOCOL_MIN       1
#define GHCB_PROTOCOL_MAX       2
#define GHCB_DEFAULT_USAGE      0

/* MSR protocol: the low 12 bits of the GHCB MSR select the function */
#define GHCB_MSR_INFO_MASK          0xfffULL
#define GHCB_MSR_SEV_INFO_RESP      0x001
#define GHCB_MSR_SEV_INFO_REQ       0x002
#define GHCB_MSR_CPUID_REQ          0x004
#define GHCB_MSR_CPUID_RESP         0x005
#define GHCB_MSR_AP_RESET_HOLD_REQ  0x006
#define GHCB_MSR_AP_RESET_HOLD_RESP 0x007
#define GHCB_MSR_PREF_GPA_REQ       0x010
#define GHCB_MSR_PREF_GPA_RESP      0x011
#define GHCB_MSR_PREF_GPA_NONE      0xfffffffffffffULL
#define GHCB_MSR_REG_GPA_REQ        0x012
#define GHCB_MSR_REG_GPA_RESP       0x013
#define GHCB_MSR_PSC_REQ            0x014
#define GHCB_MSR_PSC_RESP           0x015
#define GHCB_MSR_HV_FT_REQ          0x080
#define GHCB_MSR_HV_FT_RESP         0x081
#define GHCB_MSR_TERM_REQ           0x100

#define GHCB_HV_FT_SNP              (1ULL << 0)
#define GHCB_HV_FT_SNP_AP_CREATION  (1ULL << 1)

/* sw_exit_info_1 of a NAE event: 0 ok, 1 exception in sw_exit_info_2, 2 malformed */
#define GHCB_RESULT_OK              0
#define GHCB_RESULT_EXCEPTION       1
#define GHCB_RESULT_MALFORMED       2

/* sw_exit_info_2 of a malformed request */
#define GHCB_ERR_NOT_REGISTERED     1
#define GHCB_ERR_MISSING_INPUT      2
#define GHCB_ERR_INVALID_USAGE      3
#define GHCB_ERR_INVALID_SCRATCH    4
#define GHCB_ERR_INVALID_INPUT      5
#define GHCB_ERR_INVALID_EVENT      6

/* software exit codes (VMGEXIT NAE events) */
#define SVM_VMGEXIT_MMIO_READ           0x80000001
#define SVM_VMGEXIT_MMIO_WRITE          0x80000002
#define SVM_VMGEXIT_NMI_COMPLETE        0x80000003
#define SVM_VMGEXIT_AP_HLT_LOOP         0x80000004
#define SVM_VMGEXIT_AP_JUMP_TABLE       0x80000005
#define SVM_VMGEXIT_SET_AP_JUMP_TABLE   0
#define SVM_VMGEXIT_GET_AP_JUMP_TABLE   1
#define SVM_VMGEXIT_PSC                 0x80000010
#define SVM_VMGEXIT_GUEST_REQUEST       0x80000011
#define SVM_VMGEXIT_EXT_GUEST_REQUEST   0x80000012
#define SVM_VMGEXIT_AP_CREATION         0x80000013
#define SVM_VMGEXIT_AP_CREATE_ON_INIT   0
#define SVM_VMGEXIT_AP_CREATE           1
#define SVM_VMGEXIT_AP_DESTROY          2
#define SVM_VMGEXIT_HV_FEATURES         0x8000fffd
#define SVM_VMGEXIT_TERM_REQUEST        0x8000fffe
#define SVM_VMGEXIT_UNSUPPORTED_EVENT   0x8000ffff

/* IOIO exit information (APM vol. 2, 15.10.2) */
#define IOIO_TYPE_IN    (1 << 0)
#define IOIO_TYPE_STR   (1 << 2)
#define IOIO_TYPE_REP   (1 << 3)
#define IOIO_DATA_8     (1 << 4)
#define IOIO_DATA_16    (1 << 5)
#define IOIO_DATA_32    (1 << 6)

/* why a vCPU is parked by an AP reset hold request */
#define SEV_AP_RESET_HOLD_NONE  0
#define SEV_AP_RESET_HOLD_MSR   1
#define SEV_AP_RESET_HOLD_NAE   2

#endif /* I386_SEV_EMU_H */
