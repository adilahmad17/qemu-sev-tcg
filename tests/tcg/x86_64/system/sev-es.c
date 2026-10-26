/*
 * Emulated SEV-ES guest test: boots as an SEV-ES guest from an IGVM file
 * (mkigvm.py) and exercises the #VC exception, the GHCB MSR protocol and
 * the VMGEXIT NAE events of the sev-emu object. Every console character of
 * this test travels through #VC and a GHCB IOIO event.
 *
 * Copyright (C) 2026 The ASTERISC Research Lab
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <inttypes.h>
#include <minilib.h>

#define MSR_SEV_STATUS      0xc0010131
#define MSR_GHCB            0xc0010130
#define MSR_APIC_BASE       0x1b
#define MSR_KERNEL_GS_BASE  0xc0000102
#define MSR_X2APIC_ID       0x802

#define SVM_EXIT_READ_DR7   0x27
#define SVM_EXIT_WRITE_DR7  0x37
#define SVM_EXIT_RDTSC      0x6e
#define SVM_EXIT_RDPMC      0x6f
#define SVM_EXIT_CPUID      0x72
#define SVM_EXIT_INVD       0x76
#define SVM_EXIT_HLT        0x78
#define SVM_EXIT_IOIO       0x7b
#define SVM_EXIT_MSR        0x7c
#define SVM_EXIT_VMMCALL    0x81
#define SVM_EXIT_WBINVD     0x89
#define SVM_EXIT_MONITOR    0x8a
#define SVM_EXIT_MWAIT      0x8b
#define SVM_VMGEXIT_MMIO_READ   0x80000001
#define SVM_VMGEXIT_MMIO_WRITE  0x80000002
#define SVM_VMGEXIT_AP_CREATION 0x80000013
#define SVM_VMGEXIT_HV_FEATURES 0x8000fffd
#define SVM_VMGEXIT_TERM_REQUEST 0x8000fffe
#define SVM_EXIT_PAGE_NOT_VALIDATED 0x404
#define SVM_VMGEXIT_PSC         0x80000010
#define SVM_VMGEXIT_GUEST_REQUEST 0x80000011
#define GHCB_MSR_PSC_REQ    0x014
#define GHCB_MSR_PSC_RESP   0x015
#define GHCB_MSR_REG_GPA_REQ 0x012
#define GHCB_MSR_REG_GPA_RESP 0x013
#define SNP_SECRETS_GPA     0x3fe000
#define SNP_CPUID_GPA       0x3ff000

#define GHCB_MSR_INFO_REQ   0x002
#define GHCB_MSR_INFO_RESP  0x001
#define GHCB_MSR_CPUID_REQ  0x004
#define GHCB_MSR_CPUID_RESP 0x005
#define GHCB_MSR_HV_FT_REQ  0x080
#define GHCB_MSR_HV_FT_RESP 0x081
#define GHCB_MSR_TERM_REQ   0x100

struct ghcb {
    uint8_t  reserved_0[0xcb];
    uint8_t  cpl;
    uint8_t  reserved_1[0x12c];
    uint64_t rax;                   /* 0x1f8 */
    uint8_t  reserved_2[0x108];
    uint64_t rcx, rdx, rbx;         /* 0x308 */
    uint8_t  reserved_3[0x70];
    uint64_t sw_exit_code;          /* 0x390 */
    uint64_t sw_exit_info_1;
    uint64_t sw_exit_info_2;
    uint64_t sw_scratch;
    uint8_t  reserved_4[0x38];
    uint64_t xcr0;                  /* 0x3e8 */
    uint8_t  valid_bitmap[16];      /* 0x3f0 */
    uint64_t x87_state_gpa;
    uint8_t  reserved_5[0x3f8];
    uint8_t  shared_buffer[0x7f0];  /* 0x800 */
    uint8_t  reserved_6[0xa];
    uint16_t protocol_version;
    uint32_t ghcb_usage;
} __attribute__((packed));

_Static_assert(sizeof(struct ghcb) == 4096, "ghcb");
_Static_assert(__builtin_offsetof(struct ghcb, sw_exit_code) == 0x390, "ghcb");
_Static_assert(__builtin_offsetof(struct ghcb, shared_buffer) == 0x800, "ghcb");

static struct ghcb ghcb_page __attribute__((aligned(4096)));

#define GHCB_BIT(f) (__builtin_offsetof(struct ghcb, f) / 8)
#define GHCB_SET(g, f, v) do { (g)->f = (v); \
    (g)->valid_bitmap[GHCB_BIT(f) / 8] |= 1 << (GHCB_BIT(f) % 8); } while (0)

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void wrmsr(uint32_t msr, uint64_t val)
{
    asm volatile("wrmsr" : : "c"(msr), "a"((uint32_t)val),
                 "d"((uint32_t)(val >> 32)) : "memory");
}

static inline void vmgexit(void)
{
    asm volatile("rep; vmmcall" : : : "memory");
}

static uint64_t ghcb_msr_protocol(uint64_t req)
{
    wrmsr(MSR_GHCB, req);
    vmgexit();
    return rdmsr(MSR_GHCB);
}

static void ghcb_clear(struct ghcb *g)
{
    for (int i = 0; i < 16; i++) {
        g->valid_bitmap[i] = 0;
    }
    g->protocol_version = 2;
    g->ghcb_usage = 0;
}

/* a NAE event through the GHCB page; returns sw_exit_info_1 */
static uint64_t ghcb_call(struct ghcb *g, uint64_t code, uint64_t info1,
                          uint64_t info2)
{
    GHCB_SET(g, sw_exit_code, code);
    GHCB_SET(g, sw_exit_info_1, info1);
    GHCB_SET(g, sw_exit_info_2, info2);
    wrmsr(MSR_GHCB, (uint64_t)g);
    vmgexit();
    return g->sw_exit_info_1;
}

static void ghcb_ioio_out(uint16_t port, unsigned size, uint32_t val)
{
    struct ghcb *g = &ghcb_page;
    uint64_t info = ((uint64_t)port << 16) | (1 << 7) |
                    (size == 1 ? 1 << 4 : size == 2 ? 1 << 5 : 1 << 6);
    ghcb_clear(g);
    GHCB_SET(g, rax, val);
    ghcb_call(g, SVM_EXIT_IOIO, info, 0);
}

static uint32_t ghcb_ioio_in(uint16_t port, unsigned size)
{
    struct ghcb *g = &ghcb_page;
    uint64_t info = ((uint64_t)port << 16) | (1 << 7) | 1 |
                    (size == 1 ? 1 << 4 : size == 2 ? 1 << 5 : 1 << 6);
    ghcb_clear(g);
    GHCB_SET(g, rax, 0);
    ghcb_call(g, SVM_EXIT_IOIO, info, 0);
    return g->rax;
}

/* ---- #VC handler ---- */

struct vc_regs {
    uint64_t r11, r10, r9, r8, rdi, rsi, rbp, rbx, rdx, rcx, rax;
    uint64_t error_code;
    uint64_t rip, cs, rflags, rsp, ss;
};

void vc_handler_c(struct vc_regs *r);

/* the #VC entry: the frame of struct vc_regs, the C handler, iretq */
static __attribute__((naked)) void vc_entry(void)
{
    asm volatile(
        "push %rax\n    push %rcx\n    push %rdx\n    push %rbx\n    push %rbp\n"
        "push %rsi\n    push %rdi\n    push %r8\n    push %r9\n    push %r10\n"
        "push %r11\n"
        "mov %rsp, %rdi\n"
        "mov %rsp, %rbx\n"
        "and $-16, %rsp\n"
        "call vc_handler_c\n"
        "mov %rbx, %rsp\n"
        "pop %r11\n    pop %r10\n    pop %r9\n    pop %r8\n    pop %rdi\n    pop %rsi\n"
        "pop %rbp\n    pop %rbx\n    pop %rdx\n    pop %rcx\n    pop %rax\n"
        "add $8, %rsp\n"
        "iretq\n");
}

/* any other exception: exit with code 0x41 (the OUT itself goes through #VC) */
static __attribute__((naked)) void fault_entry(void)
{
    asm volatile(
        "mov $0x41, %eax\n"
        "out %al, $0xf4\n"
        "1:  hlt\n"
        "jmp 1b\n");
}

static unsigned vc_counts[16];
static unsigned vc_unexpected;
static uint64_t vc_last_unexpected;
static uint64_t vc_last_cr2;      /* of the last "page not validated" #VC */

/* PVALIDATE: returns EAX, *no_change = CF */
static int pvalidate(void *va, int huge, int validate, int *no_change)
{
    int rc;
    uint8_t cf;
    asm volatile(".byte 0xf2, 0x0f, 0x01, 0xff\n\tsetc %1"
                 : "=a"(rc), "=r"(cf) : "a"(va), "c"(huge), "d"(validate)
                 : "memory", "cc");
    *no_change = cf;
    return rc;
}

/* RMPADJUST: returns EAX */
static int rmpadjust(void *va, int huge, uint64_t attrs)
{
    int rc;
    asm volatile(".byte 0xf3, 0x0f, 0x01, 0xfe"
                 : "=a"(rc) : "a"(va), "c"(huge), "d"(attrs) : "memory", "cc");
    return rc;
}

static unsigned vc_class(uint64_t code)
{
    switch (code) {
    case SVM_EXIT_CPUID:
        return 1;
    case SVM_EXIT_MSR:
        return 2;
    case SVM_EXIT_IOIO:
        return 3;
    case SVM_EXIT_HLT:
        return 4;
    case SVM_EXIT_WBINVD:
        return 5;
    case SVM_EXIT_INVD:
        return 6;
    case SVM_EXIT_RDPMC:
        return 7;
    case SVM_EXIT_MONITOR:
        return 8;
    case SVM_EXIT_MWAIT:
        return 9;
    case SVM_EXIT_VMMCALL:
        return 10;
    case SVM_EXIT_READ_DR7:
        return 11;
    case SVM_EXIT_WRITE_DR7:
        return 12;
    case SVM_EXIT_RDTSC:
        return 13;
    case SVM_EXIT_PAGE_NOT_VALIDATED:
        return 14;
    default:
        return 0;
    }
}

#define IOIO_SIZE(size) ((size) == 1 ? 1 << 4 : (size) == 2 ? 1 << 5 : 1 << 6)
#define IOIO_INFO(port, size, in, str, rep) \
    (((uint64_t)(port) << 16) | (1 << 9) | IOIO_SIZE(size) | \
     ((rep) ? 1 << 3 : 0) | ((str) ? 1 << 2 : 0) | ((in) ? 1 : 0))

/*
 * INS and OUTS: the elements go through the GHCB shared buffer in the order
 * the instruction accesses them; the handler moves RSI/RDI by the direction
 * flag. Returns nonzero when the hypervisor refuses an event.
 */
static int vc_string_io(struct vc_regs *r, uint8_t op, int rep, int opsize16)
{
    struct ghcb *g = &ghcb_page;
    unsigned size = (op & 1) ? (opsize16 ? 2 : 4) : 1;
    int in = !(op & 2);
    uint16_t port = (uint16_t)r->rdx;
    uint64_t count = rep ? r->rcx : 1;
    int64_t step = (r->rflags & (1 << 10)) ? -(int64_t)size : (int64_t)size;
    uint64_t max = sizeof(g->shared_buffer) / size;

    while (count) {
        uint64_t n = count < max ? count : max;
        ghcb_clear(g);
        if (!in) {
            for (uint64_t i = 0; i < n * size; i++) {
                g->shared_buffer[i] = ((uint8_t *)r->rsi)[i % size];
                if (i % size == size - 1) {
                    r->rsi += step;
                }
            }
        }
        GHCB_SET(g, sw_scratch, (uint64_t)g->shared_buffer);
        if (ghcb_call(g, SVM_EXIT_IOIO, IOIO_INFO(port, size, in, 1, rep), n)) {
            return 1;
        }
        if (in) {
            for (uint64_t i = 0; i < n * size; i++) {
                ((uint8_t *)r->rdi)[i % size] = g->shared_buffer[i];
                if (i % size == size - 1) {
                    r->rdi += step;
                }
            }
        }
        count -= n;
        if (rep) {
            r->rcx -= n;
        }
    }
    return 0;
}

void vc_handler_c(struct vc_regs *r)
{
    struct ghcb *g = &ghcb_page;
    const uint8_t *p = (const uint8_t *)r->rip;
    unsigned prefixes = 0;
    int opsize16 = 0, rep = 0;

    vc_counts[vc_class(r->error_code)]++;
    while (*p == 0x66 || *p == 0xf3 || *p == 0xf2 || (*p & 0xf0) == 0x40) {
        if (*p == 0x66) {
            opsize16 = 1;
        }
        if (*p == 0xf3 || *p == 0xf2) {
            rep = 1;
        }
        p++;
        prefixes++;
    }

    switch (r->error_code) {
    case SVM_EXIT_CPUID:
        ghcb_clear(g);
        GHCB_SET(g, rax, (uint32_t)r->rax);
        GHCB_SET(g, rcx, (uint32_t)r->rcx);
        if ((uint32_t)r->rax == 0xd) {
            GHCB_SET(g, xcr0, 1);
        }
        ghcb_call(g, SVM_EXIT_CPUID, 0, 0);
        r->rax = (uint32_t)g->rax;
        r->rbx = (uint32_t)g->rbx;
        r->rcx = (uint32_t)g->rcx;
        r->rdx = (uint32_t)g->rdx;
        r->rip += prefixes + 2;
        return;
    case SVM_EXIT_MSR:
        ghcb_clear(g);
        GHCB_SET(g, rcx, (uint32_t)r->rcx);
        if (p[1] == 0x30) {           /* wrmsr */
            GHCB_SET(g, rax, (uint32_t)r->rax);
            GHCB_SET(g, rdx, (uint32_t)r->rdx);
            ghcb_call(g, SVM_EXIT_MSR, 1, 0);
        } else {                      /* rdmsr */
            ghcb_call(g, SVM_EXIT_MSR, 0, 0);
            r->rax = (uint32_t)g->rax;
            r->rdx = (uint32_t)g->rdx;
        }
        r->rip += prefixes + 2;
        return;
    case SVM_EXIT_IOIO: {
        uint8_t op = p[0];
        unsigned len = prefixes + 1, size;
        uint16_t port;
        if (op >= 0xe4 && op <= 0xe7) {
            port = p[1];
            len++;
        } else if (op >= 0xec && op <= 0xef) {
            port = (uint16_t)r->rdx;
        } else if (op >= 0x6c && op <= 0x6f) {
            if (vc_string_io(r, op, rep, opsize16)) {
                goto unexpected;
            }
            r->rip += len;
            return;
        } else {
            goto unexpected;
        }
        size = (op & 1) ? (opsize16 ? 2 : 4) : 1;
        if ((op & 2) == 0) {
            uint32_t v = ghcb_ioio_in(port, size);
            if (size == 1) {
                r->rax = (r->rax & ~0xffULL) | (v & 0xff);
            } else if (size == 2) {
                r->rax = (r->rax & ~0xffffULL) | (v & 0xffff);
            } else {
                r->rax = v;
            }
        } else {
            ghcb_ioio_out(port, size, (uint32_t)r->rax);
        }
        r->rip += len;
        return;
    }
    case SVM_EXIT_HLT:
        r->rip += prefixes + 1;      /* not forwarded: the test must not sleep */
        return;
    case SVM_EXIT_WBINVD:
    case SVM_EXIT_INVD:
        ghcb_clear(g);
        ghcb_call(g, r->error_code, 0, 0);
        r->rip += prefixes + 2;
        return;
    case SVM_EXIT_RDPMC:
        ghcb_clear(g);
        GHCB_SET(g, rax, (uint32_t)r->rcx);
        ghcb_call(g, SVM_EXIT_RDPMC, 0, 0);
        r->rax = (uint32_t)g->rax;
        r->rdx = (uint32_t)g->rdx;
        r->rip += prefixes + 2;
        return;
    case SVM_EXIT_MONITOR:
    case SVM_EXIT_MWAIT:
        ghcb_clear(g);
        GHCB_SET(g, rax, r->rax);
        GHCB_SET(g, rcx, r->rcx);
        GHCB_SET(g, rdx, r->rdx);
        ghcb_call(g, r->error_code, 0, 0);
        r->rip += prefixes + 3;
        return;
    case SVM_EXIT_VMMCALL:
        ghcb_clear(g);
        GHCB_SET(g, rax, r->rax);
        GHCB_SET(g, cpl, r->cs & 3);
        ghcb_call(g, SVM_EXIT_VMMCALL, 0, 0);
        r->rip += prefixes + 3;
        return;
    case SVM_EXIT_READ_DR7:
        ghcb_clear(g);
        ghcb_call(g, SVM_EXIT_READ_DR7, 0, 0);
        r->rax = g->rax;             /* the test reads DR7 into rax */
        r->rip += prefixes + 3;
        return;
    case SVM_EXIT_WRITE_DR7:
        ghcb_clear(g);
        GHCB_SET(g, rax, r->rax);
        ghcb_call(g, SVM_EXIT_WRITE_DR7, 0, 0);
        r->rip += prefixes + 3;
        return;
    case SVM_EXIT_PAGE_NOT_VALIDATED: {
        /* validate the page in CR2 and retry the instruction */
        uint64_t cr2;
        int nc;
        asm volatile("mov %%cr2, %0" : "=r"(cr2));
        vc_last_cr2 = cr2;
        if (pvalidate((void *)(cr2 & ~0xfffULL), 0, 1, &nc) != 0) {
            goto unexpected;
        }
        return;
    }
    default:
        break;
    }
unexpected:
    vc_unexpected++;
    vc_last_unexpected = r->error_code;
    /* skip two bytes and hope: the test reports the count */
    r->rip += prefixes + 2;
}

/* ---- IDT ---- */

struct idt_entry {
    uint16_t off0, sel;
    uint8_t ist, type;
    uint16_t off1;
    uint32_t off2, rsvd;
} __attribute__((packed));

#define TIMER_VECTOR 0x40

static struct idt_entry idt[TIMER_VECTOR + 1] __attribute__((aligned(16)));

static volatile unsigned timer_ticks;  /* set by the interrupt handler */

#define MSR_X2APIC_EOI          0x80b
#define MSR_X2APIC_SVR          0x80f
#define MSR_X2APIC_LVT_TIMER    0x832
#define MSR_X2APIC_TIMER_ICR    0x838
#define MSR_X2APIC_TIMER_DCR    0x83e

/* called by name from timer_entry */
static void __attribute__((used)) timer_handler_c(void)
{
    timer_ticks++;
    wrmsr(MSR_X2APIC_EOI, 0);
}

/* the APIC timer interrupt: count and EOI */
static __attribute__((naked)) void timer_entry(void)
{
    asm volatile(
        "push %rax\n    push %rcx\n    push %rdx\n    push %rbx\n    push %rsi\n"
        "push %rdi\n    push %r8\n    push %r9\n    push %r10\n    push %r11\n"
        "mov %rsp, %rbx\n"
        "and $-16, %rsp\n"
        "call timer_handler_c\n"
        "mov %rbx, %rsp\n"
        "pop %r11\n    pop %r10\n    pop %r9\n    pop %r8\n    pop %rdi\n"
        "pop %rsi\n    pop %rbx\n    pop %rdx\n    pop %rcx\n    pop %rax\n"
        "iretq\n");
}

static void set_gate(int vec, void (*fn)(void))
{
    uint64_t a = (uint64_t)fn;
    uint16_t cs;
    asm volatile("mov %%cs, %0" : "=r"(cs));
    idt[vec].off0 = a;
    idt[vec].sel = cs;
    idt[vec].ist = 0;
    idt[vec].type = 0x8e;
    idt[vec].off1 = a >> 16;
    idt[vec].off2 = a >> 32;
}

static void idt_init(void)
{
    struct { uint16_t limit; uint64_t base; } __attribute__((packed)) idtr = {
        sizeof(idt) - 1, (uint64_t)idt };
    for (int v = 0; v < 32; v++) {
        set_gate(v, fault_entry);
    }
    set_gate(29, vc_entry);
    set_gate(TIMER_VECTOR, timer_entry);
    asm volatile("lidt %0" : : "m"(idtr));
}

/* ---- the tests ---- */

static int failures;

#define CHECK(cond, ...) do { \
    if (cond) { ml_printf("ok   " __VA_ARGS__); ml_printf("\n"); } \
    else { ml_printf("FAIL " __VA_ARGS__); ml_printf("\n"); failures++; } } while (0)

static void cpuid(uint32_t leaf, uint32_t sub, uint32_t *a, uint32_t *b,
                  uint32_t *c, uint32_t *d)
{
    asm volatile("cpuid" : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                 : "a"(leaf), "c"(sub));
}

static volatile int ap_started;   /* set by the other vCPU */
static uint64_t ap_stack[512];
static uint8_t ap_vmsa[3 * 4096] __attribute__((aligned(4096)));

static void ap_entry(void)
{
    ap_started = 1;
    for (;;) {
        asm volatile("pause");
    }
}

static void vmsa_seg(uint8_t *v, unsigned off, uint16_t sel, uint16_t attrib,
                     uint32_t limit, uint64_t base)
{
    *(uint16_t *)(v + off) = sel;
    *(uint16_t *)(v + off + 2) = attrib;
    *(uint32_t *)(v + off + 4) = limit;
    *(uint64_t *)(v + off + 8) = base;
}

static void test_ap_creation(void)
{
    struct ghcb *g = &ghcb_page;
    uint8_t *v = ap_vmsa + 4096;
    uint64_t cr0, cr3, cr4;
    uint16_t cs, ds;

    /* the VMSA must not be 2 MB aligned */
    if (((uint64_t)v & 0x1fffff) == 0) {
        v += 4096;
    }
    for (int i = 0; i < 4096; i++) {
        v[i] = 0;
    }
    asm volatile("mov %%cs, %0" : "=r"(cs));
    asm volatile("mov %%ds, %0" : "=r"(ds));
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    asm volatile("mov %%cr4, %0" : "=r"(cr4));
    vmsa_seg(v, 0x00, ds, 0xc93, 0xffffffff, 0);  /* es */
    vmsa_seg(v, 0x10, cs, 0xa9b, 0xffffffff, 0);  /* cs: 64-bit code */
    vmsa_seg(v, 0x20, ds, 0xc93, 0xffffffff, 0);  /* ss */
    vmsa_seg(v, 0x30, ds, 0xc93, 0xffffffff, 0);  /* ds */
    vmsa_seg(v, 0x40, 0, 0xc93, 0xffffffff, 0);   /* fs */
    vmsa_seg(v, 0x50, 0, 0xc93, 0xffffffff, 0);   /* gs */
    vmsa_seg(v, 0x70, 0, 0x82, 0xffff, 0);        /* ldtr */
    vmsa_seg(v, 0x90, 0, 0x8b, 0xffff, 0);        /* tr */
    *(uint64_t *)(v + 0xd0) = 0x1d00;             /* efer: LME, LMA, NXE, SVME */
    *(uint64_t *)(v + 0x148) = cr4;
    *(uint64_t *)(v + 0x150) = cr3;
    *(uint64_t *)(v + 0x158) = cr0;
    *(uint64_t *)(v + 0x160) = 0x400;             /* dr7 */
    *(uint64_t *)(v + 0x168) = 0xffff0ff0;        /* dr6 */
    *(uint64_t *)(v + 0x170) = 0x2;               /* rflags */
    *(uint64_t *)(v + 0x178) = (uint64_t)ap_entry;
    *(uint64_t *)(v + 0x1d8) = (uint64_t)&ap_stack[511];
    *(uint64_t *)(v + 0x268) = 0x0007040600070406ULL; /* g_pat */
    *(uint64_t *)(v + 0x3b0) = 0;                 /* sev_features: SEV-ES */
    *(uint64_t *)(v + 0x3e8) = 1;                 /* xcr0 */
    *(uint32_t *)(v + 0x408) = 0x1f80;            /* mxcsr */
    *(uint16_t *)(v + 0x410) = 0x37f;             /* fcw */

    /* a 2 MB aligned VMSA is refused */
    ghcb_clear(g);
    GHCB_SET(g, rax, 0);
    ghcb_call(g, SVM_VMGEXIT_AP_CREATION, (1ULL << 32) | 1, 0x200000);
    CHECK(g->sw_exit_info_1 == 2 && g->sw_exit_info_2 == 5,
          "AP creation with a 2 MB aligned VMSA refused (%" PRIx64 "/%" PRIx64 ")",
          g->sw_exit_info_1, g->sw_exit_info_2);
    /* an unknown APIC ID is refused */
    ghcb_clear(g);
    GHCB_SET(g, rax, 0);
    ghcb_call(g, SVM_VMGEXIT_AP_CREATION, (7ULL << 32) | 1, (uint64_t)v);
    CHECK(g->sw_exit_info_1 == 2, "AP creation for APIC ID 7 refused");
    /* wrong sev_features is refused */
    ghcb_clear(g);
    GHCB_SET(g, rax, 1);
    ghcb_call(g, SVM_VMGEXIT_AP_CREATION, (1ULL << 32) | 1, (uint64_t)v);
    CHECK(g->sw_exit_info_1 == 2, "AP creation with foreign sev_features refused");

    ghcb_clear(g);
    GHCB_SET(g, rax, 0);
    ghcb_call(g, SVM_VMGEXIT_AP_CREATION, (1ULL << 32) | 1, (uint64_t)v);
    CHECK(g->sw_exit_info_1 == 0, "AP creation accepted");
    for (int i = 0; i < 100000000 && !ap_started; i++) {
        asm volatile("pause");
    }
    CHECK(ap_started, "AP started from the VMSA and ran its entry");
}

#define MSR_EFER            0xc0000080
#define EFER_SVME           (1 << 12)
#define FW_CFG_PORT_SEL     0x510
#define FW_CFG_PORT_DATA    0x511
#define FW_CFG_SIGNATURE    0x0000
#define FW_CFG_ID           0x0001

/* the GHCB protocol version field is not checked (KVM does not either) */
static void test_ghcb_version0(void)
{
    struct ghcb *g = &ghcb_page;

    ghcb_clear(g);
    g->protocol_version = 0;
    ghcb_call(g, SVM_VMGEXIT_HV_FEATURES, 0, 0);
    CHECK(g->sw_exit_info_1 == 0, "NAE event with GHCB protocol version 0 (%" PRIx64 ")",
          g->sw_exit_info_1);
}

/* EFER.SVME clear: VMGEXIT (F3 and F2 forms) and VMMCALL still reach the hypervisor */
static void test_vmgexit_no_svme(void)
{
    uint64_t efer = rdmsr(MSR_EFER), resp, resp2;
    unsigned before = vc_counts[10];

    wrmsr(MSR_EFER, efer & ~EFER_SVME);
    resp = ghcb_msr_protocol(GHCB_MSR_INFO_REQ);
    wrmsr(MSR_GHCB, GHCB_MSR_HV_FT_REQ);
    asm volatile(".byte 0xf2, 0x0f, 0x01, 0xd9" : : : "memory");
    resp2 = rdmsr(MSR_GHCB);
    asm volatile("vmmcall" : : "a"(0));
    CHECK(!(rdmsr(MSR_EFER) & EFER_SVME) && (resp & 0xfff) == GHCB_MSR_INFO_RESP &&
          (resp2 & 0xfff) == GHCB_MSR_HV_FT_RESP && vc_counts[10] == before + 1,
          "VMGEXIT (F3, F2) and VMMCALL with EFER.SVME clear (%" PRIx64 " %" PRIx64 ")",
          resp, resp2);
    wrmsr(MSR_EFER, efer);
}

static void fw_cfg_select(uint16_t key)
{
    asm volatile("outw %0, %1" : : "a"(key), "Nd"((uint16_t)FW_CFG_PORT_SEL));
}

/* INS and OUTS through #VC and the string IOIO event, on the fw_cfg ports */
static void test_string_io(void)
{
    struct ghcb *g = &ghcb_page;
    static const uint16_t keys[2] = { FW_CFG_ID, FW_CFG_SIGNATURE };
    static uint8_t buf[8], outside[64] __attribute__((aligned(64)));
    static uint8_t b1;
    const void *src = keys;
    void *dst = buf;
    uint64_t n = 2;
    unsigned before = vc_counts[3];

    /* REP OUTSW of two selectors: the last one written is in effect */
    asm volatile("rep outsw" : "+S"(src), "+c"(n) : "d"(FW_CFG_PORT_SEL) : "memory");
    CHECK(n == 0 && src == keys + 2 && vc_counts[3] == before + 1,
          "REP OUTSW: one #VC for 2 elements, RSI and RCX advanced");
    n = 4;
    asm volatile("rep insb" : "+D"(dst), "+c"(n) : "d"(FW_CFG_PORT_DATA) : "memory");
    CHECK(n == 0 && dst == buf + 4 && buf[0] == 'Q' && buf[1] == 'E' &&
          buf[2] == 'M' && buf[3] == 'U',
          "REP INSB of 4 bytes reads the fw_cfg signature in order");

    /* DF set: the elements land at descending addresses */
    fw_cfg_select(FW_CFG_SIGNATURE);
    dst = buf + 7;
    n = 4;
    asm volatile("std\n\trep insb\n\tcld"
                 : "+D"(dst), "+c"(n) : "d"(FW_CFG_PORT_DATA) : "memory");
    CHECK(n == 0 && dst == buf + 3 && buf[7] == 'Q' && buf[6] == 'E' &&
          buf[5] == 'M' && buf[4] == 'U',
          "REP INSB with DF set stores downwards");

    /* INSB without REP: one element, RCX untouched */
    fw_cfg_select(FW_CFG_SIGNATURE);
    dst = &b1;
    n = 5;
    asm volatile("insb" : "+D"(dst), "+c"(n) : "d"(FW_CFG_PORT_DATA) : "memory");
    CHECK(b1 == 'Q' && dst == &b1 + 1 && n == 5,
          "INSB without REP reads one byte (%x)", b1);

    /* the hypervisor side: count 0, a scratch area outside the GHCB, bad scratch areas */
    ghcb_clear(g);
    GHCB_SET(g, sw_scratch, (uint64_t)g->shared_buffer);
    ghcb_call(g, SVM_EXIT_IOIO, IOIO_INFO(FW_CFG_PORT_DATA, 1, 1, 1, 1), 0);
    CHECK(g->sw_exit_info_1 == 0, "string IOIO of 0 elements succeeds");
    fw_cfg_select(FW_CFG_SIGNATURE);
    ghcb_clear(g);
    GHCB_SET(g, sw_scratch, (uint64_t)outside);
    ghcb_call(g, SVM_EXIT_IOIO, IOIO_INFO(FW_CFG_PORT_DATA, 1, 1, 1, 1), 4);
    CHECK(g->sw_exit_info_1 == 0 && outside[0] == 'Q' && outside[3] == 'U',
          "string IOIO with a scratch area outside the GHCB");
    ghcb_clear(g);
    GHCB_SET(g, sw_scratch, (uint64_t)g->shared_buffer + 8);
    ghcb_call(g, SVM_EXIT_IOIO, IOIO_INFO(FW_CFG_PORT_DATA, 1, 1, 1, 1),
              sizeof(g->shared_buffer));
    CHECK(g->sw_exit_info_1 == 2 && g->sw_exit_info_2 == 4,
          "string IOIO past the end of the shared buffer is refused");
    ghcb_clear(g);
    GHCB_SET(g, sw_scratch, (uint64_t)outside);
    ghcb_call(g, SVM_EXIT_IOIO, IOIO_INFO(FW_CFG_PORT_DATA, 4, 1, 1, 1), 16 * 1024 + 1);
    CHECK(g->sw_exit_info_1 == 2 && g->sw_exit_info_2 == 4,
          "string IOIO over 64 KiB outside the GHCB is refused");
    ghcb_clear(g);
    ghcb_call(g, SVM_EXIT_IOIO, IOIO_INFO(FW_CFG_PORT_DATA, 1, 1, 1, 1), 1);
    CHECK(g->sw_exit_info_1 == 2 && g->sw_exit_info_2 == 2,
          "string IOIO without a scratch area is missing input");
}

#if defined(SEV_SNP_TEST)
struct snp_cpuid_fn {
    uint32_t eax_in, ecx_in;
    uint64_t xcr0_in, xss_in;
    uint32_t eax, ebx, ecx, edx;
    uint64_t reserved;
} __attribute__((packed));

struct snp_cpuid_table {
    uint32_t count, reserved1;
    uint64_t reserved2;
    struct snp_cpuid_fn fn[64];
} __attribute__((packed));

static const struct snp_cpuid_fn *cpuid_page_find(uint32_t leaf, uint32_t sub)
{
    const struct snp_cpuid_table *t = (const void *)SNP_CPUID_GPA;
    for (uint32_t i = 0; i < t->count && i < 64; i++) {
        if (t->fn[i].eax_in == leaf && t->fn[i].ecx_in == sub) {
            return &t->fn[i];
        }
    }
    return 0;
}

static uint8_t snp_pages[4 * 4096] __attribute__((aligned(4096)));
static uint8_t snp_vmsa[3 * 4096] __attribute__((aligned(4096)));

/*
 * An AP started again from a VMSA keeps its GHCB MSR (the VMCB holds it,
 * not the VMSA): note the value found, then leave a mark for the next start.
 */
#define AP_GHCB_MARK        0x3fd000ULL
static volatile uint64_t ap_ghcb_seen;   /* set by the other vCPU */

static void ap_entry_ghcb(void)
{
    ap_ghcb_seen = rdmsr(MSR_GHCB);
    wrmsr(MSR_GHCB, AP_GHCB_MARK);
    ap_started = 1;
    for (;;) {
        asm volatile("pause");
    }
}

static uint64_t psc_msr(void *va, unsigned op)
{
    return ghcb_msr_protocol(GHCB_MSR_PSC_REQ | ((uint64_t)va & 0x000ffffffffff000ULL) |
                             ((uint64_t)op << 52));
}

static uint64_t psc_ghcb(void *va, unsigned op, int huge)
{
    struct ghcb *g = &ghcb_page;
    uint16_t *hdr = (uint16_t *)g->shared_buffer;
    uint64_t *entries = (uint64_t *)(g->shared_buffer + 8);
    ghcb_clear(g);
    hdr[0] = 0;
    hdr[1] = 0;
    *(uint32_t *)(hdr + 2) = 0;
    entries[0] = ((uint64_t)va & 0x000ffffffffff000ULL) | ((uint64_t)op << 52) |
                 (huge ? 1ULL << 56 : 0);
    GHCB_SET(g, sw_scratch, (uint64_t)g->shared_buffer);
    ghcb_call(g, SVM_VMGEXIT_PSC, 0, 0);
    return g->sw_exit_info_2;
}

int main(void)
{
    struct ghcb *g = &ghcb_page;
    const struct snp_cpuid_table *table = (const void *)SNP_CPUID_GPA;
    const struct snp_cpuid_fn *fn;
    const uint8_t *secrets = (const uint8_t *)SNP_SECRETS_GPA;
    uint64_t v, resp;
    unsigned before;
    int rc, nc, nz;

    idt_init();
    ml_printf("sev-snp: SNP emulation test\n");

    v = rdmsr(MSR_SEV_STATUS);
    CHECK(v == 0x7, "SEV_STATUS is SEV+ES+SNP (%" PRIx64 ")", v);
    resp = ghcb_msr_protocol(GHCB_MSR_HV_FT_REQ);
    CHECK((resp >> 12) == 3, "hypervisor features: SNP and AP creation (%" PRIx64 ")", resp);

    /* the CPUID page */
    CHECK(table->count > 0 && table->count <= 64, "CPUID page has %u entries", table->count);
    fn = cpuid_page_find(0x8000001f, 0);
    CHECK(fn && (fn->eax & 0x1a) == 0x1a && (fn->ebx & 0x3f) == 51,
          "CPUID page: 0x8000001f with SEV, ES, SNP and C-bit 51");
    fn = cpuid_page_find(0xd, 0);
    CHECK(fn && fn->ebx == 0x240 && fn->xcr0_in == 1, "CPUID page: leaf 0xd.0 convention");
    fn = cpuid_page_find(1, 0);
    CHECK(fn && (fn->ecx & (1 << 21)) && !(fn->ecx & (1 << 3)),
          "CPUID page: leaf 1 has x2APIC, not MONITOR");
    CHECK(cpuid_page_find(0x80000000, 0) && cpuid_page_find(7, 0),
          "CPUID page: leaves 0x80000000 and 7");

    /* the secrets page: version and a VMPCK0 */
    nz = 0;
    for (int i = 0x20; i < 0x40; i++) {
        nz |= secrets[i];
    }
    CHECK(*(const uint32_t *)secrets == 3 && nz, "secrets page: version 3, VMPCK0 set");

    /* GHCB registration */
    resp = ghcb_msr_protocol(GHCB_MSR_REG_GPA_REQ | (uint64_t)g);
    CHECK(resp == (GHCB_MSR_REG_GPA_RESP | (uint64_t)g), "GHCB registered (%" PRIx64 ")", resp);

    /*
     * The validation check applies to private (C=1) mappings: set the C-bit
     * in the 2 MB page-table entry that maps the test pages, as a guest does.
     */
    {
        uint64_t cr3, *pml4, *pdpt, *pd;
        uint64_t addr = (uint64_t)snp_pages;
        asm volatile("mov %%cr3, %0" : "=r"(cr3));
        pml4 = (uint64_t *)(cr3 & ~0xfffULL);
        pdpt = (uint64_t *)(pml4[(addr >> 39) & 511] & 0x000ffffffffff000ULL);
        pd = (uint64_t *)(pdpt[(addr >> 30) & 511] & 0x000ffffffffff000ULL);
        pd[(addr >> 21) & 511] |= 1ULL << 51;
        asm volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");
    }

    /* PVALIDATE on launched (validated) pages: no change */
    rc = pvalidate(snp_pages, 0, 1, &nc);
    CHECK(rc == 0 && nc == 1, "PVALIDATE of a launched page: no change (rc %d cf %d)", rc, nc);
    /* rescind, then touch: #VC page-not-validated with CR2, the handler validates */
    rc = pvalidate(snp_pages, 0, 0, &nc);
    CHECK(rc == 0 && nc == 0, "PVALIDATE rescind (rc %d cf %d)", rc, nc);
    before = vc_counts[14];
    snp_pages[16] = 0x5a;
    CHECK(vc_counts[14] == before + 1 && (vc_last_cr2 & ~0xfffULL) == (uint64_t)snp_pages &&
          snp_pages[16] == 0x5a,
          "access to an unvalidated page: #VC 0x404, CR2 %" PRIx64 ", retried", vc_last_cr2);
    rc = pvalidate(snp_pages, 0, 1, &nc);
    CHECK(rc == 0 && nc == 1, "the handler's validation counts: no change now");
    /* the APM: bits 11:0 of the address and ECX bits 31:1 are ignored */
    rc = pvalidate(snp_pages + 7, 0, 1, &nc);
    CHECK(rc == 0 && nc == 1,
          "PVALIDATE of an unaligned address: its page (rc %d cf %d)", rc, nc);
    rc = pvalidate(snp_pages, 2, 1, &nc);
    CHECK(rc == 0 && nc == 1, "PVALIDATE uses ECX bit 0 only (rc %d cf %d)", rc, nc);
    if ((uint64_t)snp_pages & 0x1fffff) {
        rc = pvalidate(snp_pages, 1, 1, &nc);
        CHECK(rc == 1,
              "PVALIDATE of a 2M page that is not 2M aligned fails (rc %d)", rc);
    }

    /* page-state changes: shared pages cannot be validated */
    resp = psc_msr(snp_pages + 4096, 2);
    CHECK((resp & 0xfff) == GHCB_MSR_PSC_RESP && (resp >> 32) == 0, "MSR PSC to shared (%" PRIx64 ")", resp);
    rc = pvalidate(snp_pages + 4096, 0, 1, &nc);
    CHECK(rc == 1, "PVALIDATE of a shared page fails (rc %d)", rc);
    resp = psc_msr(snp_pages + 4096, 7);
    CHECK((resp >> 32) != 0, "MSR PSC with an invalid operation fails (%" PRIx64 ")", resp);
    resp = psc_ghcb(snp_pages + 4096, 1, 0);
    CHECK(resp == 0, "GHCB PSC back to private (%" PRIx64 ")", resp);
    rc = pvalidate(snp_pages + 4096, 0, 1, &nc);
    CHECK(rc == 0 && nc == 0, "PVALIDATE after PSC to private (rc %d cf %d)", rc, nc);
    resp = psc_ghcb((void *)0x7fffff000000ULL, 2, 0);
    CHECK(resp != 0, "GHCB PSC outside guest RAM fails (%" PRIx64 ")", resp);
    resp = psc_ghcb(snp_pages + 3 * 4096, 2, 1);
    CHECK(resp != 0, "GHCB PSC of a misaligned 2M entry fails (%" PRIx64 ")", resp);

    /* RMPADJUST */
    rc = rmpadjust(snp_pages + 2 * 4096, 0, 1 | (1 << 16));
    CHECK(rc == 0, "RMPADJUST VMSA attribute for VMPL1 (rc %d)", rc);
    rc = rmpadjust(snp_pages + 2 * 4096, 0, 0 | (1 << 16));
    CHECK(rc == 2, "RMPADJUST for VMPL0 fails with permission (rc %d)", rc);
    /* bits 11:0 are ignored (OVMF's VMPL0 probe passes such an address) */
    rc = rmpadjust(snp_pages + 2 * 4096 + 0x194, 0, 1);
    CHECK(rc == 0, "RMPADJUST of an unaligned address adjusts its page (rc %d)", rc);
    if ((uint64_t)snp_pages & 0x1fffff) {
        rc = rmpadjust(snp_pages, 1, 1);
        CHECK(rc == 1,
              "RMPADJUST of a 2M page that is not 2M aligned fails (rc %d)", rc);
    }
    /* the VMPL check comes before the translation: no page fault */
    rc = rmpadjust((void *)0x7fffff000000ULL, 0, 0);
    CHECK(rc == 2,
          "RMPADJUST for VMPL0 of an unmapped page fails with permission (rc %d)", rc);

    /* a guest request has no firmware behind it */
    ghcb_clear(g);
    ghcb_call(g, SVM_VMGEXIT_GUEST_REQUEST, (uint64_t)snp_pages, (uint64_t)snp_pages + 4096);
    CHECK(g->sw_exit_info_1 == 0 && g->sw_exit_info_2 != 0,
          "guest request fails cleanly (%" PRIx64 ")", g->sw_exit_info_2);

    /* AP creation: the VMSA must carry the RMPADJUST attribute and SNP features */
    {
        uint8_t *vmsa = snp_vmsa + 4096;
        uint64_t cr0, cr3, cr4;
        uint16_t cs, ds;
        if (((uint64_t)vmsa & 0x1fffff) == 0) {
            vmsa += 4096;
        }
        for (int i = 0; i < 4096; i++) {
            vmsa[i] = 0;
        }
        asm volatile("mov %%cs, %0" : "=r"(cs));
        asm volatile("mov %%ds, %0" : "=r"(ds));
        asm volatile("mov %%cr0, %0" : "=r"(cr0));
        asm volatile("mov %%cr3, %0" : "=r"(cr3));
        asm volatile("mov %%cr4, %0" : "=r"(cr4));
        vmsa_seg(vmsa, 0x00, ds, 0xc93, 0xffffffff, 0);
        vmsa_seg(vmsa, 0x10, cs, 0xa9b, 0xffffffff, 0);
        vmsa_seg(vmsa, 0x20, ds, 0xc93, 0xffffffff, 0);
        vmsa_seg(vmsa, 0x30, ds, 0xc93, 0xffffffff, 0);
        vmsa_seg(vmsa, 0x70, 0, 0x82, 0xffff, 0);
        vmsa_seg(vmsa, 0x90, 0, 0x8b, 0xffff, 0);
        *(uint64_t *)(vmsa + 0xd0) = 0x1d00;
        *(uint64_t *)(vmsa + 0x148) = cr4;
        *(uint64_t *)(vmsa + 0x150) = cr3;
        *(uint64_t *)(vmsa + 0x158) = cr0;
        *(uint64_t *)(vmsa + 0x160) = 0x400;
        *(uint64_t *)(vmsa + 0x168) = 0xffff0ff0;
        *(uint64_t *)(vmsa + 0x170) = 0x2;
        *(uint64_t *)(vmsa + 0x178) = (uint64_t)ap_entry;
        *(uint64_t *)(vmsa + 0x1d8) = (uint64_t)&ap_stack[511];
        *(uint64_t *)(vmsa + 0x268) = 0x0007040600070406ULL;
        *(uint64_t *)(vmsa + 0x3b0) = 1;              /* sev_features: SNP active */
        *(uint64_t *)(vmsa + 0x3e8) = 1;
        *(uint32_t *)(vmsa + 0x408) = 0x1f80;
        *(uint16_t *)(vmsa + 0x410) = 0x37f;
        ghcb_clear(g);
        GHCB_SET(g, rax, 1);
        ghcb_call(g, SVM_VMGEXIT_AP_CREATION, (1ULL << 32) | 1, (uint64_t)vmsa);
        CHECK(g->sw_exit_info_1 == 2, "AP creation without RMPADJUST VMSA refused");
        rc = rmpadjust(vmsa, 0, 1 | (1 << 16));
        ghcb_clear(g);
        GHCB_SET(g, rax, 0);
        ghcb_call(g, SVM_VMGEXIT_AP_CREATION, (1ULL << 32) | 1, (uint64_t)vmsa);
        CHECK(g->sw_exit_info_1 == 2, "AP creation without the SNP feature refused");
        ghcb_clear(g);
        GHCB_SET(g, rax, 1);
        ghcb_call(g, SVM_VMGEXIT_AP_CREATION, (1ULL << 32) | 1, (uint64_t)vmsa);
        CHECK(g->sw_exit_info_1 == 0 && rc == 0, "AP creation accepted");
        for (int i = 0; i < 100000000 && !ap_started; i++) {
            asm volatile("pause");
        }
        CHECK(ap_started, "AP started from the SNP VMSA");

        /* twice more: the second start finds the mark of the first */
        *(uint64_t *)(vmsa + 0x178) = (uint64_t)ap_entry_ghcb;
        for (int n = 0; n < 2; n++) {
            ap_started = 0;
            ghcb_clear(g);
            GHCB_SET(g, rax, 1);
            ghcb_call(g, SVM_VMGEXIT_AP_CREATION, (1ULL << 32) | 1,
                      (uint64_t)vmsa);
            for (int i = 0; i < 100000000 && !ap_started; i++) {
                asm volatile("pause");
            }
        }
        CHECK(ap_started && ap_ghcb_seen == AP_GHCB_MARK,
              "AP started again keeps its GHCB MSR (%" PRIx64 ")",
              ap_ghcb_seen);
    }

    ml_printf("#VC counts: cpuid %u msr %u ioio %u page-not-validated %u unexpected %u (last %" PRIx64 ")\n",
              vc_counts[1], vc_counts[2], vc_counts[3], vc_counts[14], vc_unexpected, vc_last_unexpected);
    CHECK(vc_unexpected == 0, "no unexpected #VC");
    ml_printf("sev-snp: %s\n", failures ? "FAILED" : "PASSED");
    if (failures) {
        return 1;
    }
    ghcb_msr_protocol(GHCB_MSR_TERM_REQ);
    return 0;
}
#elif defined(SEV_ES_TERM_TEST)
/* the termination request ends the VM: the harness sees QEMU exit, not a timeout */
int main(void)
{
    idt_init();
    ml_printf("sev-es-term: requesting termination\n");
    ghcb_msr_protocol(GHCB_MSR_TERM_REQ | (0ULL << 12) | (0x7bULL << 16));
    /* not reached when the hypervisor terminates the guest */
    for (;;) {
        asm volatile("pause");
    }
}
#else
int main(void)
{
    struct ghcb *g = &ghcb_page;
    uint32_t a, b, c, d;
    uint64_t resp, v, saved;
    unsigned before;

    idt_init();
    ml_printf("sev-es: #VC and GHCB test\n");

    /* SEV_STATUS and CPUID through #VC */
    v = rdmsr(MSR_SEV_STATUS);
    CHECK(v == 0x3, "SEV_STATUS is SEV+ES (%" PRIx64 ")", v);
    before = vc_counts[1];
    cpuid(0x8000001f, 0, &a, &b, &c, &d);
    CHECK(vc_counts[1] == before + 1, "CPUID raised #VC");
    CHECK((a & 0xa) == 0xa && (b & 0x3f) == 51,
          "CPUID 0x8000001f: SEV, SEV-ES, C-bit 51 (eax %x ebx %x)", a, b);
    /* MONITOR/MWAIT raise #VC, so the hypervisor does not advertise them */
    cpuid(1, 0, &a, &b, &c, &d);
    resp = ghcb_msr_protocol(GHCB_MSR_CPUID_REQ | (1ULL << 32) | (2ULL << 30));
    CHECK(!(c & (1 << 3)) && !((resp >> 32) & (1 << 3)) && (resp >> 32) == c,
          "CPUID 1 without MONITOR, #VC and MSR protocol (ecx %x)", c);

    /* the MSR protocol */
    resp = ghcb_msr_protocol(GHCB_MSR_INFO_REQ);
    CHECK((resp & 0xfff) == GHCB_MSR_INFO_RESP && ((resp >> 32) & 0xffff) <= 2 &&
          ((resp >> 48) & 0xffff) >= 2 && ((resp >> 24) & 0x3f) == 51,
          "GHCB info: version 2 supported, C-bit 51 (%" PRIx64 ")", resp);
    cpuid(0, 0, &a, &b, &c, &d);
    resp = ghcb_msr_protocol(GHCB_MSR_CPUID_REQ | (1ULL << 30));
    CHECK((resp & 0xfff) == GHCB_MSR_CPUID_RESP && (uint32_t)(resp >> 32) == b,
          "MSR protocol CPUID leaf 0 EBX matches (%x)", b);
    resp = ghcb_msr_protocol(GHCB_MSR_HV_FT_REQ);
    CHECK((resp & 0xfff) == GHCB_MSR_HV_FT_RESP && (resp >> 12) == 0,
          "hypervisor features: none without SNP (%" PRIx64 ")", resp);
    resp = ghcb_msr_protocol(0x0fe);  /* unknown: left unchanged */
    CHECK(resp == 0x0fe, "unknown MSR protocol request leaves the MSR unchanged");

    /* MSR access through #VC: APIC base read, KERNEL_GS_BASE is not intercepted */
    before = vc_counts[2];
    v = rdmsr(MSR_APIC_BASE);
    CHECK(vc_counts[2] == before + 1 && (v & 0x800), "RDMSR APIC_BASE through #VC (%" PRIx64 ")", v);
    saved = rdmsr(MSR_KERNEL_GS_BASE);
    wrmsr(MSR_KERNEL_GS_BASE, 0x1234);
    CHECK(vc_counts[2] == before + 1 && rdmsr(MSR_KERNEL_GS_BASE) == 0x1234,
          "KERNEL_GS_BASE is not intercepted");
    wrmsr(MSR_KERNEL_GS_BASE, saved);
    /* a write to the read-only SEV_STATUS MSR: the hypervisor asks for #GP */
    ghcb_clear(g);
    GHCB_SET(g, rcx, MSR_SEV_STATUS);
    GHCB_SET(g, rax, 0);
    GHCB_SET(g, rdx, 0);
    ghcb_call(g, SVM_EXIT_MSR, 1, 0);
    CHECK(g->sw_exit_info_1 == 1 && (g->sw_exit_info_2 & 0xff) == 13 && (g->sw_exit_info_2 >> 31),
          "write of a read-only MSR returns a #GP to inject (%" PRIx64 ")", g->sw_exit_info_2);

    /* GHCB field validation */
    ghcb_clear(g);
    ghcb_call(g, SVM_EXIT_MSR, 0, 0);          /* rcx missing */
    CHECK(g->sw_exit_info_1 == 2 && g->sw_exit_info_2 == 2,
          "MSR event without RCX is malformed/missing input");
    ghcb_clear(g);
    ghcb_call(g, 0x12345, 0, 0);
    CHECK(g->sw_exit_info_1 == 2 && g->sw_exit_info_2 == 6, "unknown exit code is an invalid event");
    ghcb_clear(g);
    g->ghcb_usage = 1;
    ghcb_call(g, SVM_EXIT_WBINVD, 0, 0);
    CHECK(g->sw_exit_info_1 == 2 && g->sw_exit_info_2 == 3, "non-default GHCB usage is refused");
    g->ghcb_usage = 0;

    /* intercepted instructions */
    /*
     * HLT is an automatic exit, not a #VC: the vCPU halts until an interrupt,
     * here a one-shot x2APIC timer interrupt.
     */
    {
        unsigned ticks = timer_ticks;
        before = vc_counts[4];
        wrmsr(MSR_APIC_BASE, rdmsr(MSR_APIC_BASE) | (1 << 10));
        wrmsr(MSR_X2APIC_SVR, 0x1ff);
        wrmsr(MSR_X2APIC_TIMER_DCR, 0xb);
        wrmsr(MSR_X2APIC_LVT_TIMER, TIMER_VECTOR);
        wrmsr(MSR_X2APIC_TIMER_ICR, 1000000);
        asm volatile("sti\n\thlt\n\tcli" : : : "memory");
        wrmsr(MSR_X2APIC_LVT_TIMER, 1 << 16);
        CHECK(vc_counts[4] == before && timer_ticks == ticks + 1,
              "HLT halts without #VC until the timer interrupt");
    }
    before = vc_counts[5];
    asm volatile("wbinvd");
    CHECK(vc_counts[5] == before + 1, "WBINVD raised #VC and the event succeeded");
    before = vc_counts[6];
    asm volatile("invd");
    CHECK(vc_counts[6] == before + 1, "INVD raised #VC");
    before = vc_counts[7];
    asm volatile("rdpmc" : "=a"(a), "=d"(d) : "c"(0));
    CHECK(vc_counts[7] == before + 1 && a == 0 && d == 0, "RDPMC raised #VC and returned zero");
    before = vc_counts[8];
    asm volatile("monitor" : : "a"(ap_stack), "c"(0), "d"(0));
    CHECK(vc_counts[8] == before + 1, "MONITOR raised #VC");
    before = vc_counts[9];
    asm volatile("mwait" : : "a"(0), "c"(0));
    CHECK(vc_counts[9] == before + 1, "MWAIT raised #VC");
    before = vc_counts[10];
    asm volatile("vmmcall" : : "a"(0));
    CHECK(vc_counts[10] == before + 1, "VMMCALL (without REP) raised #VC");
    before = vc_counts[11];
    asm volatile("mov %%dr7, %0" : "=a"(v));
    CHECK(vc_counts[11] == before + 1 && v == 0x400, "DR7 read raised #VC (%" PRIx64 ")", v);
    before = vc_counts[12];
    asm volatile("mov %0, %%dr7" : : "a"(0x400ULL));
    CHECK(vc_counts[12] == before + 1, "DR7 write raised #VC");
    before = vc_counts[0] + vc_counts[13];
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    CHECK(vc_counts[0] + vc_counts[13] == before, "RDTSC is not intercepted");
    /* XSETBV is not intercepted (needs CR4.OSXSAVE) */
    asm volatile("mov %%cr4, %0" : "=r"(v));
    asm volatile("mov %0, %%cr4" : : "r"(v | (1 << 18)));
    before = vc_unexpected;
    asm volatile("xsetbv" : : "a"(1), "c"(0), "d"(0));
    CHECK(vc_unexpected == before, "XSETBV is not intercepted");

    /* MMIO events: a RAM buffer written and read through the GHCB */
    {
        static uint64_t mmio_buf __attribute__((aligned(8)));
        uint64_t *scratch = (uint64_t *)g->shared_buffer;
        mmio_buf = 0;
        ghcb_clear(g);
        *scratch = 0x1122334455667788ULL;
        GHCB_SET(g, sw_scratch, (uint64_t)scratch);
        ghcb_call(g, SVM_VMGEXIT_MMIO_WRITE, (uint64_t)&mmio_buf, 8);
        CHECK(g->sw_exit_info_1 == 0 && mmio_buf == 0x1122334455667788ULL,
              "MMIO write through the scratch buffer (%" PRIx64 ")", mmio_buf);
        mmio_buf = 0xcafef00d;
        ghcb_clear(g);
        *scratch = 0;
        GHCB_SET(g, sw_scratch, (uint64_t)scratch);
        ghcb_call(g, SVM_VMGEXIT_MMIO_READ, (uint64_t)&mmio_buf, 4);
        CHECK(g->sw_exit_info_1 == 0 && (uint32_t)*scratch == 0xcafef00d,
              "MMIO read through the scratch buffer (%" PRIx64 ")", *scratch);
        ghcb_clear(g);
        GHCB_SET(g, sw_scratch, (uint64_t)g);  /* inside the GHCB but not the shared buffer */
        ghcb_call(g, SVM_VMGEXIT_MMIO_READ, (uint64_t)&mmio_buf, 4);
        CHECK(g->sw_exit_info_1 == 2 && g->sw_exit_info_2 == 4, "scratch inside the GHCB header is refused");
    }

    test_string_io();
    test_ghcb_version0();
    test_vmgexit_no_svme();

    /* HV_FEATURES NAE */
    ghcb_clear(g);
    ghcb_call(g, SVM_VMGEXIT_HV_FEATURES, 0, 0);
    CHECK(g->sw_exit_info_1 == 0 && g->sw_exit_info_2 == 0, "HV_FEATURES event");

    /* the C-bit in a page-table entry is ignored by the walker */
    {
        uint64_t cr3, *pml4, *pdpt, *pd;
        static uint8_t cbit_buf[64] __attribute__((aligned(64)));
        uint64_t addr = (uint64_t)cbit_buf;
        asm volatile("mov %%cr3, %0" : "=r"(cr3));
        pml4 = (uint64_t *)(cr3 & ~0xfffULL);
        pdpt = (uint64_t *)(pml4[(addr >> 39) & 511] & 0x000ffffffffff000ULL);
        pd = (uint64_t *)(pdpt[(addr >> 30) & 511] & 0x000ffffffffff000ULL);
        cbit_buf[0] = 0x5a;
        pd[(addr >> 21) & 511] |= 1ULL << 51;
        asm volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");
        cbit_buf[1] = cbit_buf[0] + 1;
        CHECK(cbit_buf[1] == 0x5b, "access through a PDE with the C-bit set");
        pd[(addr >> 21) & 511] &= ~(1ULL << 51);
        asm volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");
    }

    test_ap_creation();

    ml_printf("#VC counts: cpuid %u msr %u ioio %u hlt %u wbinvd %u invd %u rdpmc %u "
              "monitor %u mwait %u vmmcall %u dr7 %u/%u unexpected %u (last %" PRIx64 ")\n",
              vc_counts[1], vc_counts[2], vc_counts[3], vc_counts[4], vc_counts[5], vc_counts[6],
              vc_counts[7], vc_counts[8], vc_counts[9], vc_counts[10], vc_counts[11], vc_counts[12],
              vc_unexpected, vc_last_unexpected);
    CHECK(vc_unexpected == 0, "no unexpected #VC");
    ml_printf("sev-es: %s\n", failures ? "FAILED" : "PASSED");
    if (failures) {
        return 1;               /* isa-debug-exit through #VC and the GHCB */
    }
    /* no firmware programmed the ACPI ports: an SEV-ES guest ends with a termination request */
    ghcb_msr_protocol(GHCB_MSR_TERM_REQ);
    return 0;
}
#endif
