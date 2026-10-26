# qemu-sev-tcg

A fork of QEMU 11.1.2 that emulates the guest-visible interface of AMD SEV, SEV-ES and SEV-SNP under the TCG accelerator. It requires neither SEV hardware nor KVM and serves the functional testing of confidential-VM software, in particular the [Saguaro](https://github.com/ASTERISC-Release/saguaro) library OS. The branch `dev-sev` (default) contains the changes; `main` is QEMU v11.1.2 unmodified.

## Features

- The object types `sev-emu` (SEV; SEV-ES with policy bit 2) and `sev-snp-emu` (SEV-SNP), configured like `sev-guest` and `sev-snp-guest`.
- Guest-visible state: `SEV_STATUS`, CPUID leaf 0x8000001F, and the C-bit in page tables.
- SEV-ES: the `#VC` exception for CPUID, RDMSR/WRMSR, IN/OUT (including string forms), WBINVD, RDPMC, MONITOR/MWAIT, VMMCALL and DR7 accesses; the GHCB MSR protocol; the `VMGEXIT` events; AP creation, reset hold and wake-up.
- SEV-SNP: the CPUID and secrets pages, `PVALIDATE`, `RMPADJUST`, page-state changes, and a `#VC` for the first access to an unvalidated private page.
- Launch from an IGVM file or from a firmware image passed with `-bios` (OVMF metadata pages for SEV-SNP), with kernel hashes (`kernel-hashes=on`) and the launch measurement of SEV.
- `XSAVEC` and the compacted form of `XRSTOR` in TCG.
- Guests: Linux 6.8 and the Saguaro SEV PAL.

| Guest mode | Firmware or image | vCPUs |
|---|---|---|
| SEV | `OVMF.fd` | 1, 2 |
| SEV | `OVMF.amdsev.fd` (`kernel-hashes=on`) | 1 |
| SEV-ES | `OVMF.fd` | 1, 2 |
| SEV-ES | `OVMF.amdsev.fd` (`kernel-hashes=on`) | 1 |
| SEV-SNP | `OVMF.fd` | 1, 2, 4 |
| SEV-SNP | `OVMF.amdsev.fd` (`kernel-hashes=on`) | 1, 2 |
| SEV-SNP | OVMF IGVM file | 1, 2 |
| SEV, SEV-SNP | Saguaro IGVM image | 1, 2, 4 |

## Build

The build requires a C toolchain, git, ninja, Python 3 with `venv`, and Rust 1.80 or newer (libigvm). On Ubuntu or Debian:

    ./build.sh --install-deps    # installs the packages with apt-get, then builds
    ./build.sh                   # builds when the packages are installed

`build.sh` builds libigvm from a pinned release and QEMU for `x86_64-softmmu` with IGVM support, and installs them into `./prefix` (`--prefix DIR`, `--jobs N`). The installed `qemu-system-x86_64` locates its ROMs in `../share/qemu` and is used from its installation directory. The script finishes by checking the emulated SEV objects, the TCG accelerator and the ROMs.

## Running a Linux guest

A guest requires a kernel with SEV guest support, an initrd, and the edk2 OVMF image (`OVMF.fd`, edk2 2025.11). Saguaro provides `container/sev/build-sev-tools.sh guest firmware` (run in its development container, `container/run.sh`), which downloads and verifies an Ubuntu 24.04 kernel (6.8), builds a minimal initrd, and downloads OVMF 2025.11 into the `sev-tools/` directory.

    qemu-system-x86_64 -accel tcg -cpu max -M q35 -smp 2 -m 2G \
        -object sev-emu,id=sev0,cbitpos=51,reduced-phys-bits=1,policy=0x1 \
        -machine confidential-guest-support=sev0 \
        -bios OVMF.fd -kernel vmlinuz -initrd initrd.img \
        -append "console=ttyS0" -nographic -net none

The guest reaches its init within a few seconds. The kernel log contains `Memory Encryption Features active: AMD SEV`. The other modes change the `-object` argument:

| Mode | `-object` |
|---|---|
| SEV-ES | `sev-emu,id=sev0,cbitpos=51,reduced-phys-bits=1,policy=0x5` |
| SEV-SNP | `sev-snp-emu,id=sev0,cbitpos=51,reduced-phys-bits=1,policy=0x30000` |

The kernel log then reads `AMD SEV SEV-ES` and `AMD SEV SEV-ES SEV-SNP`, respectively. With `OVMF.amdsev.fd`, `kernel-hashes=on` is added to the object.

## Running Saguaro

In a Saguaro checkout, with `<prefix>` the installation directory of this build:

    scripts/install.sh --sev --graphics disabled
    export SAGUARO_ACCEL=tcg QEMU_PATH=<prefix>/bin/qemu-system-x86_64
    CI-Examples/helloworld/exec.sh --sev-snp        # or --sev
    test/quick.sh sev-snp --tier smoke              # or sev; --tier regression runs the LibOS core list

`CI-Examples/<name>/exec.sh` and `test/sev/test-sev.sh` accept the same two variables. Saguaro's GitHub workflow `sev-emulated-x86_64.yml` builds this fork and runs the regression tier nightly.

## Tests

The check-tcg guests under `tests/tcg/x86_64/system/` exercise the emulated protocols and instructions:

    make -C build/tests/tcg/x86_64-softmmu run-sev-es run-sev-es-term run-sev-snp run-xsavec

## Credits and license

The `sev-emulated` object, the MSR and C-bit handling, the launch state machine and the launch measurement derive from the RFC "TCG-emulated AMD SEV" by Tommaso Califano (qemu-devel, March 2026); the commits retain his authorship. The remaining changes are by the ASTERISC Research Lab. QEMU is licensed under GPL-2.0-or-later (`COPYING`).
