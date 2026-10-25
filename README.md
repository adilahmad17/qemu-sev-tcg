# qemu-sev-tcg: emulated AMD SEV, SEV-ES and SEV-SNP for QEMU TCG

A fork of QEMU 11.1.2 that emulates the guest-visible interface of AMD's confidential VMs (SEV, SEV-ES,
SEV-SNP) in software, under TCG. It needs no SEV hardware and no KVM, so software that targets SEV guests can be
tested on any machine, including CI runners. It was written for the SEV PAL of
[Saguaro](https://github.com/ASTERISC-Release/saguaro) (ASTERISC Research Lab, ASU) and is not tied to it.

**It is a functional emulation, not a secure one.** There is no attestation (a guest request fails as a
firmware error would), no memory encryption or isolation (the host can read guest memory; the C-bit is
bookkeeping), no launch measurement a report could be checked against, and no VMPL model. It tests that a guest
uses the SEV interface correctly. It does not replace a run on SEV hardware.

## What it adds

Branches: `main` is the unmodified QEMU v11.1.2; `dev-sev` (the default branch) has the changes.

- Object types `sev-emu` (plain SEV, and SEV-ES with the policy bit) and `sev-snp-emu` (SEV-SNP), used like
  `sev-guest` and `sev-snp-guest`, with the guest loaded from an IGVM file:
  `-accel tcg -M q35,confidential-guest-support=sev0,igvm-cfg=igvm0 -object sev-snp-emu,id=sev0,cbitpos=51,reduced-phys-bits=1,policy=0x30000
  -object igvm-cfg,id=igvm0,file=guest.igvm`. They need `-accel tcg` and refuse KVM.
- Guest-visible state: `SEV_STATUS` (0x1, 0x3, 0x7), CPUID 0x8000001F, the C-bit in page tables.
- SEV-ES: `#VC` (vector 29) for the intercepted instructions (CPUID, RDMSR/WRMSR, IN/OUT, HLT, WBINVD, RDPMC,
  MONITOR/MWAIT, VMMCALL, DR7), the GHCB MSR protocol and the `VMGEXIT` events, answered as KVM answers them,
  and AP creation from a VMSA.
- SEV-SNP: the CPUID and secrets pages, `PVALIDATE`, `RMPADJUST`, page-state changes, and `#VC` for an access to
  a private page that is not validated.
- The launch state machine and measurement of plain SEV from the upstream RFC (see below), and a fix that
  measures plain SEV guests loaded from an IGVM file after the load.
- Tests: `tests/tcg/x86_64/system/` has a small SEV-ES and SEV-SNP guest (`sev-es.c`, `sev-es-term.c`, built into an
  IGVM file by `mkigvm.py`).

## Build

Linux with a C toolchain, git, ninja, Python 3, and Rust (1.80 or newer, for libigvm). On Ubuntu or Debian:

    ./build.sh --install-deps      # installs the packages with apt-get, then builds
    ./build.sh                     # when the packages are already there

`build.sh` builds libigvm from a pinned release, configures a QEMU with only `x86_64-softmmu` and IGVM
support, builds and installs it into `./prefix` (`--prefix DIR`, `--jobs N` change that), and checks that the
emulated SEV objects, the TCG accelerator and the ROMs are present. A cold build takes a few minutes on a
workstation. Keep the installed binary where it is: it finds its ROMs in `../share/qemu`.

The tests of the emulation are the targets `run-sev-es`, `run-sev-es-term` and `run-sev-snp` of
`build/tests/tcg/x86_64-softmmu`.

## Use

With [Saguaro](https://github.com/ASTERISC-Release/saguaro), whose launcher selects these objects under
`SAGUARO_ACCEL=tcg`:

    export SAGUARO_ACCEL=tcg QEMU_PATH=$PWD/prefix/bin/qemu-system-x86_64
    CI-Examples/helloworld/exec.sh --sev-snp        # or --sev
    test/quick.sh sev-snp --tier smoke

## Credits and license

The `sev-emulated` object, the MSR/C-bit handling, the launch state machine and the launch measurement are from the
upstream RFC "TCG-emulated AMD SEV" by Tommaso Califano (qemu-devel, March 2026); the commits keep his authorship.
The rest is by the ASTERISC Research Lab. QEMU is licensed under GPL-2.0-or-later; see `COPYING`.
