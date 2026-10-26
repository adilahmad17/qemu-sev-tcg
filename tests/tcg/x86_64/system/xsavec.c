/*
 * XSAVEC and the compacted form of XRSTOR
 *
 * The test loads a known state into the x87, SSE and AVX registers and the
 * other components of XCR0, saves it with XSAVE (standard form) and with
 * XSAVEC (compacted form) for several requested-feature bitmaps (RFBM), and
 * compares the two images component by component at the offsets of CPUID
 * leaf 0xD.  It restores the compacted images with XRSTOR, over another
 * state, and checks the registers, the components left in their initial
 * configuration and the ones outside RFBM.  It restores hand-made compacted
 * images, and checks the header checks of XRSTOR.
 *
 * It also builds as a Linux program (-DXSAVEC_NATIVE, for example
 * gcc -O1 -DXSAVEC_NATIVE -mgeneral-regs-only -fno-builtin xsavec.c), so
 * that the images of a real CPU ("img" lines) can be compared with QEMU's.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifdef XSAVEC_NATIVE
#define _GNU_SOURCE
#endif
#include <stdint.h>

#ifdef XSAVEC_NATIVE
#include <stdio.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#define ml_printf printf
#else
#include <minilib.h>
#endif

#define AREA_SIZE   8192
#define HDR         512
#define EXT         576
#define COMPACTED   (1ULL << 63)

#define FP          (1ULL << 0)
#define SSE         (1ULL << 1)
#define YMM         (1ULL << 2)
#define BNDREGS     (1ULL << 3)
#define BNDCSR      (1ULL << 4)
#define PKRU        (1ULL << 9)

/* the user state components the test knows: x87 to AVX-512, and PKRU */
#define KNOWN       0x2ffULL

static uint8_t img_p[AREA_SIZE] __attribute__((aligned(64)));
static uint8_t img_q[AREA_SIZE] __attribute__((aligned(64)));
static uint8_t std_p[AREA_SIZE] __attribute__((aligned(64)));
static uint8_t std_q[AREA_SIZE] __attribute__((aligned(64)));
static uint8_t cmp_c[AREA_SIZE + 64] __attribute__((aligned(64)));
static uint8_t res_r[AREA_SIZE] __attribute__((aligned(64)));
static uint8_t tmp_t[AREA_SIZE + 64] __attribute__((aligned(64)));
static uint8_t fx[512] __attribute__((aligned(64)));
static uint8_t ymm[16 * 32] __attribute__((aligned(64)));
static uint8_t va[4096] __attribute__((aligned(64)));
static uint8_t vb[4096] __attribute__((aligned(64)));

static uint64_t xcr0;
static uint32_t csize[64], coff[64], calign[64];
static int checks, failures;

/* set around the instructions that may fault, and by the fault handlers */
volatile uint64_t recover_rip;  /* volatile: written by the handlers */
volatile int fault_vec;         /* volatile: written by the handlers */

static void fill(uint8_t *p, int v, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        p[i] = v;
    }
}

static void copy(uint8_t *d, const uint8_t *s, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        d[i] = s[i];
    }
}

static int same(const uint8_t *a, const uint8_t *b, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static int all(const uint8_t *p, int v, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        if (p[i] != v) {
            return 0;
        }
    }
    return 1;
}

/*
 * A buffer for XSAVE: a filler, and a clear header (XSAVE writes only
 * XSTATE_BV; the rest of the header says which form the image is in).
 */
static void prep_std(uint8_t *p)
{
    fill(p, 0xee, AREA_SIZE);
    fill(p + HDR, 0, EXT - HDR);
}

static uint64_t ld64(const uint8_t *p)
{
    return *(const uint64_t *)p;
}

static void st64(uint8_t *p, uint64_t v)
{
    *(uint64_t *)p = v;
}

static uint32_t ld32(const uint8_t *p)
{
    return *(const uint32_t *)p;
}

static void st32(uint8_t *p, uint32_t v)
{
    *(uint32_t *)p = v;
}

static void check(int ok, const char *what, uint64_t a, uint64_t b)
{
    checks++;
    if (!ok) {
        failures++;
        ml_printf("FAIL: %s (%lx %lx)\n", what, a, b);
    }
}

static void cpuid(uint32_t leaf, uint32_t sub, uint32_t *r)
{
    asm volatile("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3])
                 : "a"(leaf), "c"(sub));
}

static uint64_t xgetbv0(void)
{
    uint32_t lo, hi;

    asm volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    return lo | (uint64_t)hi << 32;
}

static void xsave(void *p, uint64_t m)
{
    asm volatile("xsave64 (%0)" : : "r"(p), "a"((uint32_t)m),
                 "d"((uint32_t)(m >> 32)) : "memory");
}

static void xsavec(void *p, uint64_t m)
{
    asm volatile("xsavec64 (%0)" : : "r"(p), "a"((uint32_t)m),
                 "d"((uint32_t)(m >> 32)) : "memory");
}

static void xrstor(void *p, uint64_t m)
{
    asm volatile("xrstor64 (%0)" : : "r"(p), "a"((uint32_t)m),
                 "d"((uint32_t)(m >> 32)) : "memory");
}

static void fxsave(void *p)
{
    asm volatile("fxsave64 (%0)" : : "r"(p) : "memory");
}

/* run XRSTOR or XSAVEC; return the vector of the exception it raised, or 0 */
static int try_xrstor(void *p, uint64_t m)
{
    fault_vec = 0;
    asm volatile("lea 1f(%%rip), %%rcx\n\t"
                 "mov %%rcx, %0\n\t"
                 "xrstor64 (%1)\n"
                 "1:\n"
                 : "=m"(recover_rip)
                 : "r"(p), "a"((uint32_t)m), "d"((uint32_t)(m >> 32))
                 : "rcx", "memory");
    recover_rip = 0;
    return fault_vec;
}

static int try_xsavec(void *p, uint64_t m)
{
    fault_vec = 0;
    asm volatile("lea 1f(%%rip), %%rcx\n\t"
                 "mov %%rcx, %0\n\t"
                 "xsavec64 (%1)\n"
                 "1:\n"
                 : "=m"(recover_rip)
                 : "r"(p), "a"((uint32_t)m), "d"((uint32_t)(m >> 32))
                 : "rcx", "memory");
    recover_rip = 0;
    return fault_vec;
}

static void read_ymm(uint8_t *p)
{
    asm volatile("vmovdqu %%ymm0, 0(%0)\n\t"   "vmovdqu %%ymm1, 32(%0)\n\t"
                 "vmovdqu %%ymm2, 64(%0)\n\t"  "vmovdqu %%ymm3, 96(%0)\n\t"
                 "vmovdqu %%ymm4, 128(%0)\n\t" "vmovdqu %%ymm5, 160(%0)\n\t"
                 "vmovdqu %%ymm6, 192(%0)\n\t" "vmovdqu %%ymm7, 224(%0)\n\t"
                 "vmovdqu %%ymm8, 256(%0)\n\t" "vmovdqu %%ymm9, 288(%0)\n\t"
                 "vmovdqu %%ymm10, 320(%0)\n\t" "vmovdqu %%ymm11, 352(%0)\n\t"
                 "vmovdqu %%ymm12, 384(%0)\n\t" "vmovdqu %%ymm13, 416(%0)\n\t"
                 "vmovdqu %%ymm14, 448(%0)\n\t" "vmovdqu %%ymm15, 480(%0)\n\t"
                 : : "r"(p) : "memory");
}

static void write_ymm(const uint8_t *p)
{
    asm volatile("vmovdqu 0(%0), %%ymm0\n\t"   "vmovdqu 32(%0), %%ymm1\n\t"
                 "vmovdqu 64(%0), %%ymm2\n\t"  "vmovdqu 96(%0), %%ymm3\n\t"
                 "vmovdqu 128(%0), %%ymm4\n\t" "vmovdqu 160(%0), %%ymm5\n\t"
                 "vmovdqu 192(%0), %%ymm6\n\t" "vmovdqu 224(%0), %%ymm7\n\t"
                 "vmovdqu 256(%0), %%ymm8\n\t" "vmovdqu 288(%0), %%ymm9\n\t"
                 "vmovdqu 320(%0), %%ymm10\n\t" "vmovdqu 352(%0), %%ymm11\n\t"
                 "vmovdqu 384(%0), %%ymm12\n\t" "vmovdqu 416(%0), %%ymm13\n\t"
                 "vmovdqu 448(%0), %%ymm14\n\t" "vmovdqu 480(%0), %%ymm15\n\t"
                 : : "r"(p) : "memory");
}

/* load the x87 registers with FLDT: ST(i) from the image at 32 + 16 * i */
static void write_x87(const uint8_t *img)
{
    asm volatile("fninit\n\t"
                 "fldcw (%0)\n\t"
                 "fldt 144(%0)\n\t" "fldt 128(%0)\n\t" "fldt 112(%0)\n\t"
                 "fldt 96(%0)\n\t"  "fldt 80(%0)\n\t"  "fldt 64(%0)\n\t"
                 "fldt 48(%0)\n\t"  "fldt 32(%0)\n\t"
                 : : "r"(img) : "memory");
}

static void write_mxcsr(const uint8_t *img)
{
    asm volatile("ldmxcsr (%0)" : : "r"(img + 24) : "memory");
}

/* offset of component @c (2 or more) in a compacted area of @comp */
static uint32_t coffc(uint64_t comp, int c)
{
    uint32_t off = EXT;
    int i;

    for (i = 2; i < c; i++) {
        if ((comp >> i) & 1) {
            if (calign[i]) {
                off = (off + 63) & ~63;
            }
            off += csize[i];
        }
    }
    if (calign[c]) {
        off = (off + 63) & ~63;
    }
    return off;
}

/* size of a compacted area of @comp */
static uint32_t csizec(uint64_t comp)
{
    uint32_t size = EXT;
    int i;

    for (i = 2; i < 63; i++) {
        if ((comp >> i) & 1) {
            size = coffc(comp, i) + csize[i];
        }
    }
    return size;
}

/*
 * The bytes of component @c of an image (standard or compacted form): the
 * x87 registers and control fields, the XMM registers and MXCSR, or the
 * extended component, or its initial configuration when XSTATE_BV[c] is
 * clear.  Returns the length.
 */
static int view(const uint8_t *img, int c, uint8_t *out)
{
    uint64_t bv = ld64(img + HDR), comp = ld64(img + HDR + 8);
    int compacted = (comp & COMPACTED) != 0;
    int n = 0, i;

    if (c == 0) {
        if (bv & FP) {
            copy(out, img, 24);
            for (i = 0; i < 8; i++) {
                copy(out + 24 + 10 * i, img + 32 + 16 * i, 10);
            }
            /* FOP is left out: QEMU does not store it */
            out[6] = out[7] = 0;
        } else {
            fill(out, 0, 104);
            out[0] = 0x7f;
            out[1] = 0x03;
        }
        return 104;
    }
    if (c == 1) {
        if (bv & SSE) {
            copy(out, img + 160, 256);
        } else {
            fill(out, 0, 256);
        }
        if (!compacted || (bv & SSE)) {
            copy(out + 256, img + 24, 4);
        } else {
            st32(out + 256, 0x1f80);
        }
        return 260;
    }
    /* reserved bytes: 63:16 of BNDCSR, 7:4 of PKRU */
    n = c == 4 ? 16 : c == 9 ? 4 : csize[c];
    if (bv & (1ULL << c)) {
        copy(out, img + (compacted ? coffc(comp, c) : coff[c]), n);
    } else {
        fill(out, 0, n);
    }
    return n;
}

/* the initial configuration of component @c, in the compacted form */
static int init_view(int c, uint8_t *out)
{
    static uint8_t hdr_only[EXT];

    fill(hdr_only, 0, EXT);
    st64(hdr_only + HDR + 8, COMPACTED);
    return view(hdr_only, c, out);
}

/* a standard-form image with a pattern in every component of XCR0 */
static void make_image(uint8_t *img, int seed)
{
    int i, c;

    fill(img, 0, AREA_SIZE);
    img[0] = 0x7f;                              /* FCW */
    img[1] = seed ? 0x0e : 0x02;
    img[4] = 0xff;                              /* all registers valid */
    for (i = 0; i < 8; i++) {
        uint8_t *st = img + 32 + 16 * i;
        int j;

        for (j = 0; j < 8; j++) {
            st[j] = 0x11 * (i + 1) + 0x07 * j + 0x40 * seed;
        }
        st[7] |= 0x80;                          /* normal numbers */
        st[8] = 0xff - i;                       /* exponent 0x3fxx */
        st[9] = 0x3f | (seed ? 0x80 : 0);
    }
    st32(img + 24, seed ? 0x5f80 : 0x9fc0);     /* MXCSR */
    for (i = 0; i < 256; i++) {
        img[160 + i] = i * 7 + 3 + seed * 0x55;
    }
    st64(img + HDR, xcr0);
    for (c = 2; c < 63; c++) {
        if (!((xcr0 >> c) & 1)) {
            continue;
        }
        for (i = 0; i < csize[c]; i++) {
            img[coff[c] + i] = (c << 4) + i * 13 + seed * 0x33;
        }
        if (c == 4) {
            /* BNDCFGU: base and BNDPRESERVE, not enabled */
            st64(img + coff[c], seed ? 0x6789a002 : 0x12345002);
        }
        if (c == 9) {
            /* key 0 stays accessible */
            st64(img + coff[c], seed ? 0x55555550 : 0x55555554);
        }
    }
}

/*
 * Load the state of a pattern image: XRSTOR (standard form) for all of
 * XCR0, then the x87, MXCSR and the XMM/YMM registers again with the
 * ordinary instructions.
 */
static void load_state(const uint8_t *img)
{
    static uint8_t y[16 * 32] __attribute__((aligned(64)));
    int i;

    for (i = 0; i < 16; i++) {
        copy(y + 32 * i, img + 160 + 16 * i, 16);
        copy(y + 32 * i + 16, img + coff[2] + 16 * i, 16);
    }
    xrstor((void *)img, xcr0);
    write_x87(img);
    write_mxcsr(img);
    if (xcr0 & YMM) {
        write_ymm(y);
    }
}

static void hex(uint64_t v, int digits, char *out)
{
    int i;

    for (i = digits - 1; i >= 0; i--) {
        out[i] = "0123456789abcdef"[v & 15];
        v >>= 4;
    }
    out[digits] = 0;
}

static void dump(const char *tag, uint64_t rfbm, const uint8_t *img, int len)
{
    char line[8 + 32 * 2 + 32], *p;
    int off, i;

    for (off = 0; off < len; off += 32) {
        p = line;
        hex(off, 4, p);
        p += 4;
        *p++ = ':';
        for (i = 0; i < 32 && off + i < len; i++) {
            *p++ = ' ';
            hex(img[off + i], 2, p);
            p += 2;
        }
        *p = 0;
        ml_printf("img %s %lx %s\n", tag, rfbm, line);
    }
}

static void test_cpuid(void)
{
    uint32_t r[4];
    int c;

    cpuid(0xd, 1, r);
    ml_printf("cpuid 0xd.1: eax %x ebx %x ecx %x\n", r[0], r[1], r[2]);
#ifndef XSAVEC_NATIVE
    /* no IA32_XSS components: EBX is the compacted size of XCR0 */
    check(r[1] == csizec(xcr0), "CPUID.(0xd,1).EBX: compacted size of XCR0",
          r[1], csizec(xcr0));
#endif
    for (c = 0; c < 63; c++) {
        if ((xcr0 >> c) & 1) {
            ml_printf("component %d: size %d offset %d align64 %d, "
                      "compacted offset in XCR0 %d\n",
                      c, csize[c], coff[c], calign[c],
                      c < 2 ? 0 : coffc(xcr0, c));
        }
    }
}

/*
 * XSAVEC against XSAVE, then XRSTOR of the compacted image.  The components
 * of @initmask are put in their initial configuration first (XINUSE may
 * then be clear: a real CPU leaves them out of the image).
 */
static void test_xsavec(uint64_t req, uint64_t initmask)
{
    uint64_t rfbm = req & xcr0, bv, comp, rr;
    int c, n, k, ok, f0 = failures, pass;
    uint32_t end;

    fill(tmp_t, 0, EXT);
    st64(tmp_t + HDR + 8, COMPACTED);
    load_state(img_p);
    if (initmask) {
        xrstor(tmp_t, initmask);
    }
    prep_std(std_p);
    xsave(std_p, xcr0);
    fill(cmp_c, 0xee, sizeof(cmp_c));
    xsavec(cmp_c, req);

    bv = ld64(cmp_c + HDR);
    comp = ld64(cmp_c + HDR + 8);
    check(comp == (rfbm | COMPACTED), "XCOMP_BV is RFBM | bit 63", comp, rfbm);
    check(!(bv & ~rfbm), "XSTATE_BV within RFBM", bv, rfbm);
    check(all(cmp_c + HDR + 16, 0xee, 48), "header bytes 63:16 not written",
          ld64(cmp_c + HDR + 16), 0);
    check(all(cmp_c + 416, 0xee, 96), "legacy bytes 511:416 not written",
          ld64(cmp_c + 416), 0);
    end = csizec(comp);
    check(all(cmp_c + end, 0xee, 64), "nothing written after the last "
          "component", end, 0);
    for (c = 0; c < 63; c++) {
        uint64_t m = 1ULL << c;

        if (!(xcr0 & m)) {
            continue;
        }
        if (rfbm & bv & m) {
            n = view(cmp_c, c, va);
            view(std_p, c, vb);
            check(same(va, vb, n), "component saved as by XSAVE", c, rfbm);
            if (c == 1) {
                check(ld32(cmp_c + 28) == ld32(std_p + 28),
                      "MXCSR_MASK saved", ld32(cmp_c + 28), ld32(std_p + 28));
            }
        } else if (c == 0) {
            ok = all(cmp_c, 0xee, 24) && all(cmp_c + 32, 0xee, 128);
            check(ok, "x87 area not written", c, rfbm);
        } else if (c == 1) {
            ok = all(cmp_c + 160, 0xee, 256) && all(cmp_c + 24, 0xee, 8);
            check(ok, "XMM area and MXCSR not written", c, rfbm);
        } else if (rfbm & m) {
            check(all(cmp_c + coffc(comp, c), 0xee, csize[c]),
                  "component in its initial configuration not written",
                  c, rfbm);
        }
    }
    dump(initmask ? "xsavec-init" : "xsavec",
         initmask ? initmask << 32 | rfbm : rfbm, cmp_c, end);
    /* XRSTOR wants bytes 63:16 of the header clear */
    fill(cmp_c + HDR + 16, 0, 48);

    /* restore over the other state, all of XCR0 then RFBM only */
    for (pass = 0; pass < 2; pass++) {
        rr = pass ? rfbm : xcr0;
        load_state(img_q);
        prep_std(std_q);
        xsave(std_q, xcr0);
        xrstor(cmp_c, rr);
        prep_std(res_r);
        xsave(res_r, xcr0);
        fxsave(fx);
        if (xcr0 & YMM) {
            read_ymm(ymm);
        }
        for (c = 0; c < 63; c++) {
            uint64_t m = 1ULL << c;

            if (!(xcr0 & m)) {
                continue;
            }
            n = (rr & m) ? view(cmp_c, c, va) : view(std_q, c, va);
            view(res_r, c, vb);
            check(same(va, vb, n), pass ? "XRSTOR of RFBM: component" :
                  "XRSTOR of XCR0: component", c, rfbm);
            if (c == 0) {
                /* the registers through FXSAVE (FOP left out) */
                ok = same(va, fx, 6) && same(va + 8, fx + 8, 16);
                for (k = 0; k < 8; k++) {
                    ok &= same(va + 24 + 10 * k, fx + 32 + 16 * k, 10);
                }
                check(ok, "x87 registers after XRSTOR", c, rfbm);
            } else if (c == 1) {
                ok = same(va, fx + 160, 256) && same(va + 256, fx + 24, 4);
                for (k = 0; k < 16; k++) {
                    ok &= same(va + 16 * k, ymm + 32 * k, 16);
                }
                check(ok, "XMM registers and MXCSR after XRSTOR", c, rfbm);
            } else if (c == 2) {
                ok = 1;
                for (k = 0; k < 16; k++) {
                    ok &= same(va + 16 * k, ymm + 32 * k + 16, 16);
                }
                check(ok, "YMM registers after XRSTOR", c, rfbm);
            }
        }
    }
    ml_printf("xsavec rfbm %lx init %lx: XSTATE_BV %lx XCOMP_BV %lx size %d: "
              "%s\n", rfbm, initmask, bv, comp, end,
              failures == f0 ? "ok" : "FAIL");
}

/* XRSTOR of compacted images made here from the XSAVE image */
static void test_xrstor_made(uint64_t comp, uint64_t clear)
{
    uint64_t bv;
    int c, n, f0 = failures;

    comp &= xcr0;
    bv = comp & ~clear;
    load_state(img_p);
    prep_std(std_p);
    xsave(std_p, xcr0);
    fill(tmp_t, 0xcc, sizeof(tmp_t));
    copy(tmp_t, std_p, 416);
    fill(tmp_t + 416, 0, EXT - 416);
    st64(tmp_t + HDR, bv);
    st64(tmp_t + HDR + 8, comp | COMPACTED);
    for (c = 2; c < 63; c++) {
        if ((comp >> c) & 1) {
            copy(tmp_t + coffc(comp, c), std_p + coff[c], csize[c]);
        }
    }

    load_state(img_q);
    prep_std(std_q);
    xsave(std_q, xcr0);
    xrstor(tmp_t, xcr0);
    prep_std(res_r);
    xsave(res_r, xcr0);
    for (c = 0; c < 63; c++) {
        if (!((xcr0 >> c) & 1)) {
            continue;
        }
        if ((bv >> c) & 1) {
            n = view(std_p, c, va);
        } else {
            n = init_view(c, va);
        }
        view(res_r, c, vb);
        check(same(va, vb, n), "XRSTOR of a made compacted image", c, comp);
    }
    ml_printf("xrstor compacted XCOMP_BV %lx XSTATE_BV %lx: %s\n",
              comp | COMPACTED, bv, failures == f0 ? "ok" : "FAIL");
}

/* the standard form loads MXCSR whatever XSTATE_BV[1] is */
static void test_std_mxcsr(void)
{
    load_state(img_p);
    prep_std(std_p);
    xsave(std_p, xcr0);
    copy(tmp_t, std_p, AREA_SIZE);
    st64(tmp_t + HDR, xcr0 & ~SSE);
    load_state(img_q);
    xrstor(tmp_t, xcr0);
    fxsave(fx);
    check(ld32(fx + 24) == ld32(std_p + 24), "standard XRSTOR loads MXCSR "
          "with XSTATE_BV[1] clear", ld32(fx + 24), ld32(std_p + 24));
    check(all(fx + 160, 0, 256), "standard XRSTOR, XSTATE_BV[1] clear: XMM "
          "registers initialized", 0, 0);

    /* informational: RFBM with YMM but without SSE */
    load_state(img_q);
    xrstor(tmp_t, YMM);
    fxsave(fx);
    ml_printf("info: standard XRSTOR, RFBM 4: MXCSR %x (image %x, before %x)\n",
              ld32(fx + 24), ld32(std_p + 24), ld32(img_q + 24));
}

static void gp_case(const char *what, uint64_t rr, int expect)
{
    int v;

    load_state(img_q);
    fxsave(va);
    v = try_xrstor(tmp_t, rr);
    fxsave(vb);
    check(v == expect, what, v, expect);
    if (v) {
        check(same(va + 160, vb + 160, 256) && same(va + 24, vb + 24, 4),
              "no state change on the exception", 0, 0);
    }
}

static void test_xrstor_checks(void)
{
    uint64_t bit;
    int v, f0 = failures;

    load_state(img_p);
    fill(cmp_c, 0, sizeof(cmp_c));
    xsavec(cmp_c, xcr0);

    copy(tmp_t, cmp_c, AREA_SIZE);
    gp_case("valid compacted image", xcr0, 0);

    /* a bit outside XCR0 in XCOMP_BV (bit 8 is a supervisor component) */
    bit = 1ULL << 8;
    copy(tmp_t, cmp_c, AREA_SIZE);
    st64(tmp_t + HDR + 8, ld64(tmp_t + HDR + 8) | bit);
    gp_case("#GP: XCOMP_BV bit not in XCR0", xcr0, 13);

    /* XSTATE_BV bit not in XCOMP_BV */
    copy(tmp_t, cmp_c, AREA_SIZE);
    st64(tmp_t + HDR + 8, COMPACTED | FP | SSE);
    st64(tmp_t + HDR, FP | SSE | (xcr0 & YMM));
    gp_case("#GP: XSTATE_BV bit not in XCOMP_BV", xcr0, xcr0 & YMM ? 13 : 0);

    /* XSTATE_BV bit 63 */
    copy(tmp_t, cmp_c, AREA_SIZE);
    st64(tmp_t + HDR, ld64(tmp_t + HDR) | COMPACTED);
    gp_case("#GP: XSTATE_BV bit 63", xcr0, 13);

    /* bytes 63:16 of the header */
    copy(tmp_t, cmp_c, AREA_SIZE);
    tmp_t[HDR + 16] = 1;
    gp_case("#GP: compacted, header byte 16", xcr0, 13);
    copy(tmp_t, cmp_c, AREA_SIZE);
    tmp_t[HDR + 63] = 0x80;
    gp_case("#GP: compacted, header byte 63", xcr0, 13);

    /* standard form: bytes 23:8 */
    load_state(img_p);
    prep_std(std_p);
    xsave(std_p, xcr0);
    copy(tmp_t, std_p, AREA_SIZE);
    st64(tmp_t + HDR + 8, FP | SSE);
    gp_case("#GP: standard, XCOMP_BV without bit 63", xcr0, 13);
    copy(tmp_t, std_p, AREA_SIZE);
    tmp_t[HDR + 23] = 1;
    gp_case("#GP: standard, header byte 23", xcr0, 13);
    copy(tmp_t, std_p, AREA_SIZE);
    tmp_t[HDR + 24] = 1;
    gp_case("standard, header byte 24 ignored", xcr0, 0);

    /* an empty compacted image initializes everything */
    fill(tmp_t, 0, AREA_SIZE);
    st64(tmp_t + HDR + 8, COMPACTED);
    gp_case("XCOMP_BV with bit 63 only", xcr0, 0);
    test_xrstor_made(0, 0);

    /* alignment */
    v = try_xsavec(cmp_c + 16, xcr0);
    check(v == 13, "#GP: XSAVEC to an area not aligned to 64 bytes", v, 13);
    copy(tmp_t + 32, cmp_c, AREA_SIZE);
    v = try_xrstor(tmp_t + 32, xcr0);
    check(v == 13, "#GP: compacted XRSTOR not aligned to 64 bytes", v, 13);

#ifndef XSAVEC_NATIVE
    {
        uint64_t cr4;

        asm volatile("mov %%cr4, %0" : "=r"(cr4));
        asm volatile("mov %0, %%cr4" : : "r"(cr4 & ~(1ULL << 18)));
        v = try_xsavec(cmp_c, xcr0);
        asm volatile("mov %0, %%cr4" : : "r"(cr4));
        check(v == 6, "#UD: XSAVEC with CR4.OSXSAVE clear", v, 6);
    }
#endif
    ml_printf("xrstor header checks: %s\n", failures == f0 ? "ok" : "FAIL");
}

#ifdef XSAVEC_NATIVE
static void on_fault(int sig, siginfo_t *si, void *ctx)
{
    ucontext_t *uc = ctx;

    if (!recover_rip) {
        ml_printf("unexpected signal %d\n", sig);
        _exit(2);
    }
    fault_vec = sig == SIGILL ? 6 : 13;
    uc->uc_mcontext.gregs[REG_RIP] = recover_rip;
}

static int setup(void)
{
    struct sigaction sa = { 0 };

    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, 0);
    sigaction(SIGBUS, &sa, 0);
    sigaction(SIGILL, &sa, 0);
    xcr0 = xgetbv0();
    return 0;
}
#else
struct idt_entry {
    uint16_t off0, sel;
    uint8_t ist, type;
    uint16_t off1;
    uint32_t off2, zero;
} __attribute__((packed));

static struct idt_entry idt[32] __attribute__((aligned(16)));

/* #UD and #GP: note the vector, resume at recover_rip */
asm(".text\n"
    "xs_ud_entry:\n"
    "    movl $6, fault_vec(%rip)\n"
    "    jmp 1f\n"
    "xs_gp_entry:\n"
    "    movl $13, fault_vec(%rip)\n"
    "    add $8, %rsp\n"
    "1:  push %rax\n"
    "    mov recover_rip(%rip), %rax\n"
    "    mov %rax, 8(%rsp)\n"
    "    pop %rax\n"
    "    iretq\n");

static void set_gate(int vec, uint64_t a)
{
    uint16_t cs;

    asm volatile("mov %%cs, %0" : "=r"(cs));
    idt[vec].off0 = a;
    idt[vec].sel = cs;
    idt[vec].ist = 0;
    idt[vec].type = 0x8e;
    idt[vec].off1 = a >> 16;
    idt[vec].off2 = a >> 32;
    idt[vec].zero = 0;
}

static int setup(void)
{
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) idtr = { sizeof(idt) - 1, (uint64_t)idt };
    uint64_t cr0, cr4, want, ud, gp;
    uint32_t r[4];

    asm("lea xs_ud_entry(%%rip), %0\n\t"
        "lea xs_gp_entry(%%rip), %1" : "=r"(ud), "=r"(gp));
    set_gate(6, ud);
    set_gate(13, gp);
    asm volatile("lidt %0" : : "m"(idtr));

    cpuid(1, 0, r);
    if (!(r[2] & (1 << 26))) {
        ml_printf("no XSAVE\n");
        return -1;
    }
    /* x87 and SSE on, OSFXSR, OSXMMEXCPT, OSXSAVE */
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 = (cr0 & ~((1ULL << 2) | (1ULL << 3))) | (1ULL << 1) | (1ULL << 5);
    asm volatile("mov %0, %%cr0" : : "r"(cr0));
    asm volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= (1ULL << 9) | (1ULL << 10) | (1ULL << 18);
    asm volatile("mov %0, %%cr4" : : "r"(cr4));

    cpuid(0xd, 0, r);
    want = (r[0] | (uint64_t)r[3] << 32) & KNOWN;
    asm volatile("xsetbv" : : "c"(0), "a"((uint32_t)want),
                 "d"((uint32_t)(want >> 32)));
    xcr0 = xgetbv0();
    return 0;
}

/* CPUID.(0xd,1).EBX follows XCR0 */
static void test_cpuid_xcr0(void)
{
    static const uint64_t masks[] = { FP, FP | SSE, FP | SSE | YMM,
                                      FP | PKRU, FP | SSE | YMM | PKRU };
    uint32_t r[4];
    int i;

    for (i = 0; i < sizeof(masks) / sizeof(masks[0]); i++) {
        uint64_t m = masks[i] & xcr0;

        asm volatile("xsetbv" : : "c"(0), "a"((uint32_t)m), "d"(0));
        cpuid(0xd, 1, r);
        check(r[1] == csizec(m), "CPUID.(0xd,1).EBX follows XCR0", r[1],
              csizec(m));
    }
    asm volatile("xsetbv" : : "c"(0), "a"((uint32_t)xcr0),
                 "d"((uint32_t)(xcr0 >> 32)));
}
#endif

int main(void)
{
    static const uint64_t reqs[] = {
        -1ULL, 0, FP, SSE, FP | SSE, YMM, FP | YMM, SSE | YMM,
        FP | SSE | YMM, PKRU, FP | PKRU, YMM | PKRU, SSE | YMM | PKRU,
        FP | SSE | YMM | PKRU, BNDREGS, BNDCSR, BNDREGS | BNDCSR,
        YMM | BNDCSR, FP | BNDREGS | PKRU, YMM | BNDREGS | BNDCSR | PKRU,
    };
    static const uint64_t inits[] = {
        YMM, SSE | YMM, FP, PKRU, FP | SSE | YMM | PKRU, BNDREGS | BNDCSR,
    };
    static const uint64_t made[][2] = {
        { FP | SSE, 0 }, { FP | PKRU, 0 }, { FP | YMM | PKRU, 0 },
        { SSE | BNDCSR | PKRU, 0 }, { YMM | BNDREGS, 0 }, { -1ULL, 0 },
        { -1ULL, YMM }, { -1ULL, SSE }, { -1ULL, FP }, { -1ULL, PKRU },
        { SSE | YMM, SSE }, { YMM | PKRU, YMM },
    };
    uint32_t r[4];
    int i, c;

    if (setup()) {
        return 1;
    }
    for (c = 2; c < 63; c++) {
        if ((xcr0 >> c) & 1) {
            cpuid(0xd, c, r);
            csize[c] = r[0];
            coff[c] = r[1];
            calign[c] = (r[2] >> 1) & 1;
        }
    }
    ml_printf("XCR0 %lx\n", xcr0);
    cpuid(0xd, 1, r);
    if (!(r[0] & 2)) {
        ml_printf("FAIL: CPUID.(0xd,1).EAX does not report XSAVEC\n");
        return 1;
    }
    test_cpuid();
#ifndef XSAVEC_NATIVE
    test_cpuid_xcr0();
#endif
    make_image(img_p, 0);
    make_image(img_q, 1);

    /* the instructions and XRSTOR load the same state */
    load_state(img_p);
    prep_std(std_p);
    xsave(std_p, xcr0);
    for (c = 1; c < 63; c++) {
        if ((xcr0 >> c) & 1) {
            int n = view(std_p, c, va);

            view(img_p, c, vb);
            check(same(va, vb, n), "pattern state loaded", c, 0);
        }
    }

    for (i = 0; i < sizeof(reqs) / sizeof(reqs[0]); i++) {
        test_xsavec(reqs[i], 0);
    }
    for (i = 0; i < sizeof(inits) / sizeof(inits[0]); i++) {
        test_xsavec(-1ULL, inits[i] & xcr0);
        test_xsavec(FP | SSE | YMM | PKRU, inits[i] & xcr0);
    }
    for (i = 0; i < sizeof(made) / sizeof(made[0]); i++) {
        test_xrstor_made(made[i][0], made[i][1]);
    }
    test_std_mxcsr();
    test_xrstor_checks();

    ml_printf("xsavec: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
