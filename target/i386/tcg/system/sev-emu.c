/*
 * Emulated AMD SEV-ES guest support for TCG: the #VC exception for the
 * intercepted instructions, the GHCB MSR protocol and the VMGEXIT NAE events
 * that the hypervisor answers (the functional equivalent of what KVM does in
 * arch/x86/kvm/svm/sev.c, without any protection of the guest).
 *
 * Copyright (C) 2026 The ASTERISC Research Lab
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "qemu/units.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "accel/tcg/cpu-loop.h"
#include "exec/cputlb.h"
#include "accel/tcg/cpu-mmu-index.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "system/runstate.h"
#include "tcg/helper-tcg.h"
#include "target/i386/sev.h"
#include "target/i386/sev-emu.h"

G_NORETURN void sev_emu_raise_vc(CPUX86State *env, uint32_t exit_code,
                                 uintptr_t retaddr)
{
    raise_exception_err_ra(env, EXCP1D_VC, exit_code, retaddr);
}

G_NORETURN void helper_sev_es_vc(CPUX86State *env, uint32_t exit_code)
{
    sev_emu_raise_vc(env, exit_code, GETPC());
}

/*
 * MSRs that KVM lets an SEV-ES guest access directly (no #VC): the
 * direct-access list of the SVM MSR permission map plus the SEV MSRs.
 */
bool sev_emu_msr_passthrough(uint32_t index)
{
    switch (index) {
    case MSR_EFER:
    case MSR_STAR:
    case MSR_LSTAR:
    case MSR_CSTAR:
    case MSR_FMASK:
    case MSR_FSBASE:
    case MSR_GSBASE:
    case MSR_KERNELGSBASE:
    case MSR_TSC_AUX:
    case MSR_IA32_SYSENTER_CS:
    case MSR_IA32_SYSENTER_ESP:
    case MSR_IA32_SYSENTER_EIP:
    case MSR_PAT:
    case MSR_IA32_SPEC_CTRL:
    case MSR_IA32_PRED_CMD:
    case 0x10b:                     /* IA32_FLUSH_CMD */
    case 0x1d9:                     /* IA32_DEBUGCTL */
    case 0x1db ... 0x1de:           /* last branch / interrupt from/to */
    case MSR_IA32_XSS:
    case MSR_AMD64_SEV:
    case MSR_AMD64_SEV_ES_GHCB:
        return true;
    default:
        return false;
    }
}

#define SNP_GUEST_FW_ERR_GENERIC    1

static int sev_snp_emu_psc(CPUX86State *env, hwaddr gpa, unsigned op,
                           bool huge);
static void sev_emu_nae_psc(CPUX86State *env, hwaddr ghcb_gpa, GhcbPage *ghcb);
static bool ghcb_scratch(hwaddr ghcb_gpa, GhcbPage *ghcb, unsigned size,
                         void *buf, bool to_guest);

/* ---- the GHCB page in guest memory ---- */

static void ghcb_read(hwaddr gpa, GhcbPage *ghcb)
{
    address_space_read(&address_space_memory, gpa, MEMTXATTRS_UNSPECIFIED,
                       ghcb, sizeof(*ghcb));
}

static void ghcb_write(hwaddr gpa, const GhcbPage *ghcb)
{
    address_space_write(&address_space_memory, gpa, MEMTXATTRS_UNSPECIFIED,
                        ghcb, sizeof(*ghcb));
}

static void ghcb_result(GhcbPage *ghcb, uint64_t info1, uint64_t info2)
{
    GHCB_SET(ghcb, sw_exit_info_1, info1);
    GHCB_SET(ghcb, sw_exit_info_2, info2);
}

static void ghcb_malformed(GhcbPage *ghcb, uint64_t reason)
{
    ghcb_result(ghcb, GHCB_RESULT_MALFORMED, reason);
}

static void sev_emu_terminate(uint32_t reason_set, uint32_t reason_code)
{
    warn_report("SEV-ES guest requested termination: reason set %u, code %u",
                reason_set, reason_code);
    qemu_log_mask(LOG_GUEST_ERROR,
                  "sev-emu: guest termination request %u:%u\n",
                  reason_set, reason_code);
    qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
}

/* park the vCPU after the VMGEXIT instruction */
static G_NORETURN void sev_emu_halt(CPUX86State *env, int next_eip_addend)
{
    CPUState *cs = env_cpu(env);

    env->eip += next_eip_addend;
    cs->halted = 1;
    cs->exception_index = EXCP_HLT;
    cpu_loop_exit(cs);
}

/* ---- SEV-SNP: page states ---- */

/* the RMP operations of the GHCB page-state change interface */
#define SNP_PSC_OP_PRIVATE  1
#define SNP_PSC_OP_SHARED   2
#define SNP_PSC_ERR_INVALID_HDR     1
#define SNP_PSC_ERR_INVALID_ENTRY   0x100

/* a page-state change of `op` on the page or 2M region at `gpa`; 0 or an error */
static int sev_snp_emu_psc(CPUX86State *env, hwaddr gpa, unsigned op,
                           bool huge)
{
    uint64_t size = huge ? 2 * MiB : 4096;
    uint8_t state;

    if (gpa & (size - 1) || sev_snp_emu_page_state(gpa) == SNP_PAGE_NONE ||
        sev_snp_emu_page_state(gpa + size - 4096) == SNP_PAGE_NONE) {
        qemu_log_mask(LOG_GUEST_ERROR, "sev-emu: page state change of 0x%"
                      HWADDR_PRIx " (%s): not guest RAM\n", gpa,
                      huge ? "2M" : "4K");
        return SNP_PSC_ERR_INVALID_ENTRY;
    }
    switch (op) {
    case SNP_PSC_OP_PRIVATE:
        state = SNP_PAGE_PRIVATE;
        break;
    case SNP_PSC_OP_SHARED:
        state = 0;
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "sev-emu: page state change of 0x%"
                      HWADDR_PRIx ": invalid operation %u\n", gpa, op);
        return SNP_PSC_ERR_INVALID_ENTRY;
    }
    /* either way the page is no longer validated: drop the mappings */
    for (hwaddr p = gpa; p < gpa + size; p += 4096) {
        sev_snp_emu_page_set(p, state);
    }
    tlb_flush_all_cpus_synced(env_cpu(env));
    return 0;
}

/* the PSC NAE event: a list of entries in the scratch area, processed in order */
static void sev_emu_nae_psc(CPUX86State *env, hwaddr ghcb_gpa, GhcbPage *ghcb)
{
    struct {
        uint16_t cur_entry;
        uint16_t end_entry;
        uint32_t reserved;
        uint64_t entries[(sizeof(ghcb->shared_buffer) - 8) / 8];
    } QEMU_PACKED psc;
    unsigned i;
    int error = 0;

    if (!ghcb_scratch(ghcb_gpa, ghcb, sizeof(psc), &psc, false)) {
        ghcb_malformed(ghcb, GHCB_ERR_INVALID_SCRATCH);
        return;
    }
    if (psc.end_entry >= ARRAY_SIZE(psc.entries) ||
        psc.cur_entry > psc.end_entry + 1) {
        ghcb_result(ghcb, GHCB_RESULT_OK,
                    (uint64_t)SNP_PSC_ERR_INVALID_HDR << 32);
        return;
    }
    for (i = psc.cur_entry; i <= psc.end_entry; i++) {
        uint64_t e = psc.entries[i];

        error = sev_snp_emu_psc(env, e & 0x000ffffffffff000ULL,
                                (e >> 52) & 0xf, e & (1ULL << 56));
        if (error) {
            break;
        }
        psc.cur_entry = i + 1;
    }
    /* the header tells the guest how far the hypervisor got */
    ghcb_scratch(ghcb_gpa, ghcb, 8, &psc, true);
    ghcb_result(ghcb, GHCB_RESULT_OK, (uint64_t)error << 32);
}

/* PVALIDATE and RMPADJUST operands: the page of a virtual address */
static bool sev_snp_emu_page_of(CPUX86State *env, target_ulong va,
                                target_ulong size, hwaddr *gpa,
                                uintptr_t retaddr)
{
    hwaddr paddr;

    if (va & (size - 1)) {
        return false;
    }
    if (!sev_snp_emu_translate(env, va, &paddr)) {
        /* not mapped: the instruction takes a page fault */
        env->cr[2] = va;
        raise_exception_err_ra(env, EXCP0E_PAGE, 0, retaddr);
    }
    *gpa = paddr & ~0xfffULL;
    return true;
}

#define PVALIDATE_FAIL_INPUT        1
#define PVALIDATE_FAIL_SIZEMISMATCH 6
#define RMPADJUST_FAIL_INPUT        1
#define RMPADJUST_FAIL_PERMISSION   2

/*
 * PVALIDATE: RAX the page's virtual address, ECX the size (0 4K, 1 2M), EDX
 * bit 0 validate or rescind. Returns EAX in the low 32 bits and CF ("the
 * page already was in that state") in bit 32.
 */
uint64_t helper_sev_pvalidate(CPUX86State *env, target_ulong rax,
                              target_ulong rcx, target_ulong rdx)
{
    bool huge = (uint32_t)rcx == 1, validate = rdx & 1;
    target_ulong size = huge ? 2 * MiB : 4096;
    hwaddr gpa;
    bool no_change = true;

    if ((uint32_t)rcx > 1 ||
        !sev_snp_emu_page_of(env, rax, size, &gpa, GETPC())) {
        return PVALIDATE_FAIL_INPUT;
    }
    if (huge && sev_snp_emu_page_state(gpa + size - 4096) == SNP_PAGE_NONE) {
        return PVALIDATE_FAIL_SIZEMISMATCH;
    }
    for (hwaddr p = gpa; p < gpa + size; p += 4096) {
        uint8_t state = sev_snp_emu_page_state(p);

        if (state == SNP_PAGE_NONE || !(state & SNP_PAGE_PRIVATE)) {
            /* not a private page of this guest: no RMP entry to validate */
            qemu_log_mask(LOG_GUEST_ERROR, "sev-emu: PVALIDATE of 0x%"
                          HWADDR_PRIx ": not a private page\n", p);
            return PVALIDATE_FAIL_INPUT;
        }
        if (!!(state & SNP_PAGE_VALIDATED) != validate) {
            no_change = false;
            sev_snp_emu_page_set(p, validate ? state | SNP_PAGE_VALIDATED :
                                               state & ~SNP_PAGE_VALIDATED);
        }
    }
    if (!validate) {
        /* mappings of a now unvalidated page must not survive */
        tlb_flush_all_cpus_synced(env_cpu(env));
    }
    return (uint64_t)no_change << 32;
}

/*
 * RMPADJUST: RAX the page's virtual address, ECX the size, RDX the target
 * VMPL (bits 7:0), its permissions (15:8) and the VMSA attribute (16). No
 * VMPL model here: the VMSA attribute is recorded, permissions are accepted.
 */
target_ulong helper_sev_rmpadjust(CPUX86State *env, target_ulong rax,
                                  target_ulong rcx, target_ulong rdx)
{
    bool huge = (uint32_t)rcx == 1;
    target_ulong size = huge ? 2 * MiB : 4096;
    unsigned vmpl = rdx & 0xff;
    hwaddr gpa;

    if ((uint32_t)rcx > 1 ||
        !sev_snp_emu_page_of(env, rax, size, &gpa, GETPC())) {
        return RMPADJUST_FAIL_INPUT;
    }
    if (vmpl == 0 || vmpl > 3) {
        /* only a lower VMPL can be adjusted, the guest runs at VMPL0 */
        return RMPADJUST_FAIL_PERMISSION;
    }
    for (hwaddr p = gpa; p < gpa + size; p += 4096) {
        uint8_t state = sev_snp_emu_page_state(p);

        if (state == SNP_PAGE_NONE || !(state & SNP_PAGE_PRIVATE)) {
            return RMPADJUST_FAIL_INPUT;
        }
        sev_snp_emu_page_set(p, rdx & (1 << 16) ? state | SNP_PAGE_VMSA :
                                                   state & ~SNP_PAGE_VMSA);
    }
    return 0;
}

/* ---- the MSR protocol ---- */

static void sev_emu_msr_protocol(CPUX86State *env, int next_eip_addend)
{
    uint64_t req = env->sev_ghcb_msr;
    uint64_t info = req & GHCB_MSR_INFO_MASK;
    uint64_t resp;

    switch (info) {
    case GHCB_MSR_SEV_INFO_REQ:
        resp = GHCB_MSR_SEV_INFO_RESP |
               ((uint64_t)GHCB_PROTOCOL_MAX << 48) |
               ((uint64_t)GHCB_PROTOCOL_MIN << 32) |
               ((uint64_t)(sev_get_cbit_position() & 0x3f) << 24);
        break;
    case GHCB_MSR_CPUID_REQ: {
        uint32_t fn = req >> 32;
        uint32_t reg = (req >> 30) & 3;
        uint32_t eax, ebx, ecx, edx, value;

        cpu_x86_cpuid(env, fn, 0, &eax, &ebx, &ecx, &edx);
        value = reg == 0 ? eax : reg == 1 ? ebx : reg == 2 ? ecx : edx;
        resp = GHCB_MSR_CPUID_RESP | ((uint64_t)reg << 30) |
               ((uint64_t)value << 32);
        break;
    }
    case GHCB_MSR_AP_RESET_HOLD_REQ:
        /* answered with 0x007 when a SIPI arrives (sev_emu_ap_sipi) */
        env->sev_ap_reset_hold = SEV_AP_RESET_HOLD_MSR;
        env->sev_ghcb_msr = GHCB_MSR_AP_RESET_HOLD_RESP;
        sev_emu_halt(env, next_eip_addend);
    case GHCB_MSR_HV_FT_REQ:
        resp = GHCB_MSR_HV_FT_RESP | (sev_emu_hv_features() << 12);
        break;
    case GHCB_MSR_PREF_GPA_REQ:
        if (!sev_snp_enabled()) {
            goto terminate;
        }
        resp = GHCB_MSR_PREF_GPA_RESP | (GHCB_MSR_PREF_GPA_NONE << 12);
        break;
    case GHCB_MSR_REG_GPA_REQ:
        if (!sev_snp_enabled()) {
            goto terminate;
        }
        env->sev_ghcb_registered_gpa = req & ~GHCB_MSR_INFO_MASK;
        resp = GHCB_MSR_REG_GPA_RESP | env->sev_ghcb_registered_gpa;
        break;
    case GHCB_MSR_PSC_REQ: {
        if (!sev_snp_enabled()) {
            goto terminate;
        }
        /* one 4K page: GFN in bits 51:12, operation in bits 55:52 */
        uint64_t gpa = req & 0x000ffffffffff000ULL;
        unsigned op = (req >> 52) & 0xf;
        int error = sev_snp_emu_psc(env, gpa, op, false);

        resp = GHCB_MSR_PSC_RESP | ((uint64_t)error << 32);
        break;
    }
    case GHCB_MSR_TERM_REQ:
        sev_emu_terminate((req >> 12) & 0xf, (req >> 16) & 0xff);
        sev_emu_halt(env, next_eip_addend);
    default:
        /* unknown request: the MSR is left unchanged, as KVM does */
        qemu_log_mask(LOG_GUEST_ERROR,
                      "sev-emu: unknown GHCB MSR protocol request 0x%" PRIx64 "\n",
                      req);
        return;
    }
    env->sev_ghcb_msr = resp;
    return;

terminate:
    qemu_log_mask(LOG_GUEST_ERROR,
                  "sev-emu: GHCB MSR request 0x%" PRIx64 " needs SEV-SNP\n", info);
    sev_emu_terminate(0, 0);
    sev_emu_halt(env, next_eip_addend);
}

/* ---- NAE events ---- */

/*
 * The fields the hypervisor needs for the exit code, as KVM's
 * sev_es_validate_vmgexit(): 0 when they are all there, else the GHCB_ERR_*
 * reason the guest gets back.
 */
static bool ghcb_inputs_valid(const GhcbPage *ghcb, uint64_t exit_code);

static int ghcb_inputs_check(const GhcbPage *ghcb)
{
    uint64_t exit_code = ghcb->sw_exit_code;
    bool ok;

    if (ghcb->ghcb_usage != GHCB_DEFAULT_USAGE) {
        return GHCB_ERR_INVALID_USAGE;
    }
    if (!ghcb_field_valid(ghcb, GHCB_FIELD_BIT(sw_exit_code)) ||
        !ghcb_field_valid(ghcb, GHCB_FIELD_BIT(sw_exit_info_1)) ||
        !ghcb_field_valid(ghcb, GHCB_FIELD_BIT(sw_exit_info_2))) {
        return GHCB_ERR_MISSING_INPUT;
    }
    ok = ghcb_inputs_valid(ghcb, exit_code);
    return ok ? 0 : GHCB_ERR_MISSING_INPUT;
}

static bool ghcb_inputs_valid(const GhcbPage *ghcb, uint64_t exit_code)
{
    switch (exit_code) {
    case SVM_EXIT_READ_DR7:
        return true;
    case SVM_EXIT_WRITE_DR7:
    case SVM_EXIT_RDPMC:
        return ghcb_field_valid(ghcb, GHCB_FIELD_BIT(rax));
    case SVM_EXIT_CPUID:
        if (!ghcb_field_valid(ghcb, GHCB_FIELD_BIT(rax)) ||
            !ghcb_field_valid(ghcb, GHCB_FIELD_BIT(rcx))) {
            return false;
        }
        if ((uint32_t)ghcb->rax == 0xd) {
            return ghcb_field_valid(ghcb, GHCB_FIELD_BIT(xcr0));
        }
        return true;
    case SVM_EXIT_IOIO:
        if (ghcb->sw_exit_info_1 & IOIO_TYPE_STR) {
            return ghcb_field_valid(ghcb, GHCB_FIELD_BIT(sw_scratch));
        }
        if (!(ghcb->sw_exit_info_1 & IOIO_TYPE_IN)) {
            return ghcb_field_valid(ghcb, GHCB_FIELD_BIT(rax));
        }
        return true;
    case SVM_EXIT_MSR:
        if (!ghcb_field_valid(ghcb, GHCB_FIELD_BIT(rcx))) {
            return false;
        }
        if (ghcb->sw_exit_info_1) {
            return ghcb_field_valid(ghcb, GHCB_FIELD_BIT(rax)) &&
                   ghcb_field_valid(ghcb, GHCB_FIELD_BIT(rdx));
        }
        return true;
    case SVM_EXIT_VMMCALL:
        return ghcb_field_valid(ghcb, GHCB_FIELD_BIT(rax)) &&
               ghcb_field_valid(ghcb, GHCB_FIELD_BIT(cpl));
    case SVM_EXIT_XSETBV:
    case SVM_EXIT_MWAIT:
        return ghcb_field_valid(ghcb, GHCB_FIELD_BIT(rax)) &&
               ghcb_field_valid(ghcb, GHCB_FIELD_BIT(rcx)) &&
               (exit_code == SVM_EXIT_MWAIT ||
                ghcb_field_valid(ghcb, GHCB_FIELD_BIT(rdx)));
    case SVM_EXIT_MONITOR:
        return ghcb_field_valid(ghcb, GHCB_FIELD_BIT(rax)) &&
               ghcb_field_valid(ghcb, GHCB_FIELD_BIT(rcx)) &&
               ghcb_field_valid(ghcb, GHCB_FIELD_BIT(rdx));
    case SVM_EXIT_RDTSC:
    case SVM_EXIT_RDTSCP:
    case SVM_EXIT_INVD:
    case SVM_EXIT_WBINVD:
    case SVM_EXIT_HLT:
    case SVM_VMGEXIT_NMI_COMPLETE:
    case SVM_VMGEXIT_AP_HLT_LOOP:
    case SVM_VMGEXIT_AP_JUMP_TABLE:
    case SVM_VMGEXIT_HV_FEATURES:
    case SVM_VMGEXIT_TERM_REQUEST:
    case SVM_VMGEXIT_UNSUPPORTED_EVENT:
        return true;
    case SVM_VMGEXIT_MMIO_READ:
    case SVM_VMGEXIT_MMIO_WRITE:
    case SVM_VMGEXIT_PSC:
        return ghcb_field_valid(ghcb, GHCB_FIELD_BIT(sw_scratch));
    case SVM_VMGEXIT_AP_CREATION:
        if ((uint32_t)ghcb->sw_exit_info_1 != SVM_VMGEXIT_AP_DESTROY) {
            return ghcb_field_valid(ghcb, GHCB_FIELD_BIT(rax));
        }
        return true;
    case SVM_VMGEXIT_GUEST_REQUEST:
    case SVM_VMGEXIT_EXT_GUEST_REQUEST:
        return true;
    default:
        /* an unknown exit code is reported as an invalid event below */
        return true;
    }
}

/* the scratch area: inside the GHCB's shared buffer, or a page of its own */
static bool ghcb_scratch(hwaddr ghcb_gpa, GhcbPage *ghcb, unsigned size,
                         void *buf, bool to_guest)
{
    hwaddr scratch = ghcb->sw_scratch;
    hwaddr buf_start = ghcb_gpa + offsetof(GhcbPage, shared_buffer);
    hwaddr buf_end = buf_start + sizeof(ghcb->shared_buffer);

    if (scratch >= buf_start && scratch + size <= buf_end) {
        uint8_t *p = ghcb->shared_buffer + (scratch - buf_start);
        if (to_guest) {
            memcpy(p, buf, size);
        } else {
            memcpy(buf, p, size);
        }
        return true;
    }
    if (scratch >= ghcb_gpa && scratch < ghcb_gpa + sizeof(*ghcb)) {
        return false;    /* inside the GHCB but outside the shared buffer */
    }
    if (scratch & 0xfff ? (scratch & 0xfff) + size > 0x1000 : size > 0x1000) {
        return false;    /* must not cross a page */
    }
    if (to_guest) {
        address_space_write(&address_space_memory, scratch,
                            MEMTXATTRS_UNSPECIFIED, buf, size);
    } else {
        address_space_read(&address_space_memory, scratch,
                           MEMTXATTRS_UNSPECIFIED, buf, size);
    }
    return true;
}

static void sev_emu_nae_ioio(CPUX86State *env, GhcbPage *ghcb)
{
    uint64_t info = ghcb->sw_exit_info_1;
    uint16_t port = info >> 16;
    unsigned size = info & IOIO_DATA_8 ? 1 :
                    info & IOIO_DATA_16 ? 2 : 4;
    MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;

    if (info & IOIO_TYPE_STR) {
        /* string I/O through the scratch area is not used by the guests we run */
        qemu_log_mask(LOG_UNIMP, "sev-emu: string IOIO\n");
        ghcb_malformed(ghcb, GHCB_ERR_INVALID_INPUT);
        return;
    }
    if (info & IOIO_TYPE_IN) {
        uint32_t value;
        switch (size) {
        case 1:
            value = address_space_ldub(&address_space_io, port, attrs, NULL);
            break;
        case 2:
            value = address_space_lduw_le(&address_space_io, port, attrs, NULL);
            break;
        default:
            value = address_space_ldl_le(&address_space_io, port, attrs, NULL);
            break;
        }
        /* the upper bits of RAX are preserved, the result is not sign-extended */
        GHCB_SET(ghcb, rax,
                 (ghcb->rax & ~((1ULL << (size * 8)) - 1)) | value);
    } else {
        uint32_t value = ghcb->rax;
        switch (size) {
        case 1:
            address_space_stb(&address_space_io, port, value, attrs, NULL);
            break;
        case 2:
            address_space_stw_le(&address_space_io, port, value, attrs, NULL);
            break;
        default:
            address_space_stl_le(&address_space_io, port, value, attrs, NULL);
            break;
        }
    }
    ghcb_result(ghcb, GHCB_RESULT_OK, 0);
}

static void sev_emu_nae_msr(CPUX86State *env, GhcbPage *ghcb)
{
    uint32_t index = ghcb->rcx;
    bool ok;

    if (ghcb->sw_exit_info_1) {
        uint64_t val = (uint32_t)ghcb->rax |
                       ((uint64_t)(uint32_t)ghcb->rdx << 32);
        ok = x86_wrmsr_core(env, index, val);
    } else {
        uint64_t val = 0;
        ok = x86_rdmsr_core(env, index, &val);
        GHCB_SET(ghcb, rax, (uint32_t)val);
        GHCB_SET(ghcb, rdx, (uint32_t)(val >> 32));
    }
    if (ok) {
        ghcb_result(ghcb, GHCB_RESULT_OK, 0);
    } else {
        /* the hypervisor asks the guest to inject #GP */
        ghcb_result(ghcb, GHCB_RESULT_EXCEPTION,
                    SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_EXEPT | EXCP0D_GPF);
    }
}

static void sev_emu_nae_mmio(hwaddr ghcb_gpa, GhcbPage *ghcb, bool is_write)
{
    hwaddr gpa = ghcb->sw_exit_info_1;
    uint64_t size = ghcb->sw_exit_info_2;
    uint8_t buf[8];

    if (size == 0 || size > sizeof(buf)) {
        ghcb_malformed(ghcb, GHCB_ERR_INVALID_INPUT);
        return;
    }
    if (is_write) {
        if (!ghcb_scratch(ghcb_gpa, ghcb, size, buf, false)) {
            ghcb_malformed(ghcb, GHCB_ERR_INVALID_SCRATCH);
            return;
        }
        address_space_rw(&address_space_memory, gpa, MEMTXATTRS_UNSPECIFIED,
                         buf, size, true);
    } else {
        address_space_rw(&address_space_memory, gpa, MEMTXATTRS_UNSPECIFIED,
                         buf, size, false);
        if (!ghcb_scratch(ghcb_gpa, ghcb, size, buf, true)) {
            ghcb_malformed(ghcb, GHCB_ERR_INVALID_SCRATCH);
            return;
        }
    }
    ghcb_result(ghcb, GHCB_RESULT_OK, 0);
}

static uint64_t sev_emu_ap_jump_table;

static void sev_emu_vmgexit_ghcb(CPUX86State *env, hwaddr gpa,
                                 int next_eip_addend)
{
    GhcbPage *ghcb = g_malloc(sizeof(*ghcb));
    bool halt = false;
    int reason;

    ghcb_read(gpa, ghcb);

    /*
     * The protocol version field of the page is not checked, as in KVM:
     * the version is negotiated with the MSR protocol, and OVMF leaves
     * the field 0.
     */
    reason = ghcb_inputs_check(ghcb);
    if (reason) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "sev-emu: VMGEXIT exit code 0x%" PRIx64 " with missing or "
                      "invalid GHCB fields (usage %u, reason %d)\n",
                      ghcb->sw_exit_code, ghcb->ghcb_usage, reason);
        ghcb_malformed(ghcb, reason);
        goto out;
    }

    switch (ghcb->sw_exit_code) {
    case SVM_EXIT_CPUID: {
        uint32_t eax, ebx, ecx, edx;
        uint64_t saved_xcr0 = env->xcr0;

        if ((uint32_t)ghcb->rax == 0xd) {
            /* leaf 0xD describes the XSAVE area of the XCR0 the guest passes */
            env->xcr0 = ghcb->xcr0;
        }
        cpu_x86_cpuid(env, ghcb->rax, ghcb->rcx, &eax, &ebx, &ecx, &edx);
        env->xcr0 = saved_xcr0;
        GHCB_SET(ghcb, rax, eax);
        GHCB_SET(ghcb, rbx, ebx);
        GHCB_SET(ghcb, rcx, ecx);
        GHCB_SET(ghcb, rdx, edx);
        ghcb_result(ghcb, GHCB_RESULT_OK, 0);
        break;
    }
    case SVM_EXIT_MSR:
        sev_emu_nae_msr(env, ghcb);
        break;
    case SVM_EXIT_IOIO:
        sev_emu_nae_ioio(env, ghcb);
        break;
    case SVM_EXIT_RDTSC:
    case SVM_EXIT_RDTSCP: {
        uint64_t tsc = cpu_get_tsc(env) + env->tsc_offset;
        GHCB_SET(ghcb, rax, (uint32_t)tsc);
        GHCB_SET(ghcb, rdx, (uint32_t)(tsc >> 32));
        if (ghcb->sw_exit_code == SVM_EXIT_RDTSCP) {
            GHCB_SET(ghcb, rcx, (uint32_t)env->tsc_aux);
        }
        ghcb_result(ghcb, GHCB_RESULT_OK, 0);
        break;
    }
    case SVM_EXIT_RDPMC:
        /* performance counters are not implemented by TCG */
        GHCB_SET(ghcb, rax, 0);
        GHCB_SET(ghcb, rdx, 0);
        ghcb_result(ghcb, GHCB_RESULT_OK, 0);
        break;
    case SVM_EXIT_READ_DR7:
        GHCB_SET(ghcb, rax, env->dr[7]);
        ghcb_result(ghcb, GHCB_RESULT_OK, 0);
        break;
    case SVM_EXIT_WRITE_DR7:
        /* the guest keeps its own DR7 value; the hypervisor only records it */
        ghcb_result(ghcb, GHCB_RESULT_OK, 0);
        break;
    case SVM_EXIT_XSETBV: {
        uint64_t mask = (uint32_t)ghcb->rax |
                        ((uint64_t)(uint32_t)ghcb->rdx << 32);
        uint64_t allowed = env->features[FEAT_XSAVE_XCR0_LO] |
                           ((uint64_t)env->features[FEAT_XSAVE_XCR0_HI] << 32);

        if ((uint32_t)ghcb->rcx != 0 || (mask & ~allowed) || !(mask & 1)) {
            ghcb_result(ghcb, GHCB_RESULT_EXCEPTION,
                        SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_EXEPT | EXCP0D_GPF);
            break;
        }
        env->xcr0 = mask;
        cpu_sync_avx_hflag(env);
        ghcb_result(ghcb, GHCB_RESULT_OK, 0);
        break;
    }
    case SVM_EXIT_HLT:
        ghcb_result(ghcb, GHCB_RESULT_OK, 0);
        halt = true;
        break;
    case SVM_EXIT_INVD:
    case SVM_EXIT_WBINVD:
    case SVM_EXIT_MONITOR:
    case SVM_EXIT_MWAIT:
    case SVM_EXIT_VMMCALL:
    case SVM_VMGEXIT_NMI_COMPLETE:
        ghcb_result(ghcb, GHCB_RESULT_OK, 0);
        break;
    case SVM_VMGEXIT_MMIO_READ:
        sev_emu_nae_mmio(gpa, ghcb, false);
        break;
    case SVM_VMGEXIT_MMIO_WRITE:
        sev_emu_nae_mmio(gpa, ghcb, true);
        break;
    case SVM_VMGEXIT_AP_HLT_LOOP:
        /* answered with sw_exit_info_2 = 1 when a SIPI arrives (sev_emu_ap_sipi) */
        ghcb_result(ghcb, GHCB_RESULT_OK, 0);
        env->sev_ap_reset_hold = SEV_AP_RESET_HOLD_NAE;
        halt = true;
        break;
    case SVM_VMGEXIT_AP_JUMP_TABLE:
        if (ghcb->sw_exit_info_1 == SVM_VMGEXIT_SET_AP_JUMP_TABLE) {
            sev_emu_ap_jump_table = ghcb->sw_exit_info_2;
            ghcb_result(ghcb, GHCB_RESULT_OK, 0);
        } else if (ghcb->sw_exit_info_1 == SVM_VMGEXIT_GET_AP_JUMP_TABLE) {
            ghcb_result(ghcb, GHCB_RESULT_OK, sev_emu_ap_jump_table);
        } else {
            ghcb_malformed(ghcb, GHCB_ERR_INVALID_INPUT);
        }
        break;
    case SVM_VMGEXIT_AP_CREATION:
        if (sev_emu_ap_creation((uint32_t)ghcb->sw_exit_info_1,
                                ghcb->sw_exit_info_1 >> 32,
                                ghcb->sw_exit_info_2, ghcb->rax) < 0) {
            ghcb_malformed(ghcb, GHCB_ERR_INVALID_INPUT);
        } else {
            ghcb_result(ghcb, GHCB_RESULT_OK, 0);
        }
        break;
    case SVM_VMGEXIT_HV_FEATURES:
        ghcb_result(ghcb, GHCB_RESULT_OK, sev_emu_hv_features());
        break;
    case SVM_VMGEXIT_TERM_REQUEST:
        sev_emu_terminate(ghcb->sw_exit_info_1 & 0xf,
                          (ghcb->sw_exit_info_1 >> 4) & 0xff);
        ghcb_result(ghcb, GHCB_RESULT_OK, 0);
        halt = true;
        break;
    case SVM_VMGEXIT_PSC:
        if (!sev_snp_enabled()) {
            ghcb_malformed(ghcb, GHCB_ERR_INVALID_EVENT);
            break;
        }
        sev_emu_nae_psc(env, gpa, ghcb);
        break;
    case SVM_VMGEXIT_GUEST_REQUEST:
    case SVM_VMGEXIT_EXT_GUEST_REQUEST:
        if (!sev_snp_enabled()) {
            ghcb_malformed(ghcb, GHCB_ERR_INVALID_EVENT);
            break;
        }
        /*
         * No firmware answers guest messages here (no attestation): the
         * request fails the way a firmware error does, which guests handle.
         */
        qemu_log_mask(LOG_GUEST_ERROR, "sev-emu: SNP guest request refused "
                      "(no firmware in the emulation)\n");
        ghcb_result(ghcb, GHCB_RESULT_OK,
                    (uint64_t)SNP_GUEST_FW_ERR_GENERIC << 32);
        break;
    case SVM_VMGEXIT_UNSUPPORTED_EVENT:
        qemu_log_mask(LOG_GUEST_ERROR, "sev-emu: guest reports an unsupported "
                      "event 0x%" PRIx64 "\n", ghcb->sw_exit_info_1);
        ghcb_result(ghcb, GHCB_RESULT_OK, 0);
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "sev-emu: unsupported VMGEXIT exit code "
                      "0x%" PRIx64 "\n", ghcb->sw_exit_code);
        ghcb_malformed(ghcb, GHCB_ERR_INVALID_EVENT);
        break;
    }

out:
    ghcb_write(gpa, ghcb);
    g_free(ghcb);
    if (halt) {
        sev_emu_halt(env, next_eip_addend);
    }
}

/* REP VMMCALL: the guest hands the hypervisor its GHCB MSR or GHCB page */
void helper_sev_vmgexit(CPUX86State *env, int next_eip_addend)
{
    uint64_t msr = env->sev_ghcb_msr;

    if (msr & GHCB_MSR_INFO_MASK) {
        sev_emu_msr_protocol(env, next_eip_addend);
        return;
    }
    if (env->sev_ghcb_registered_gpa &&
        msr != env->sev_ghcb_registered_gpa) {
        qemu_log_mask(LOG_GUEST_ERROR, "sev-emu: GHCB address 0x%" PRIx64
                      " differs from the registered 0x%" PRIx64 "\n",
                      msr, env->sev_ghcb_registered_gpa);
        sev_emu_terminate(0, 0);
        sev_emu_halt(env, next_eip_addend);
    }
    if (msr == 0) {
        /* no GHCB: the guest misuses VMGEXIT, nothing to answer */
        qemu_log_mask(LOG_GUEST_ERROR, "sev-emu: VMGEXIT without a GHCB\n");
        return;
    }
    sev_emu_vmgexit_ghcb(env, msr, next_eip_addend);
}
