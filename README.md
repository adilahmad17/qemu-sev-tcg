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

A stock Linux guest needs a kernel with SEV guest support, an initrd and the edk2 OVMF image. Saguaro's
`container/sev/build-sev-tools.sh` fetches them: the Ubuntu 24.04 kernel 6.8, a minimal initrd with a smoke test
(`smoke-initrd.cpio`) and OVMF 2025.11. All steps run inside Saguaro's development container (Ubuntu 24.04), which
provides the root user that `apt-get` and `build.sh --install-deps` require; nothing is installed on the host.

Prerequisites: an x86_64 Linux host with `podman` and `git`, network access, and about 10 GB of free disk space.
No root privileges are needed on the host. The first `container/run.sh` builds the container image.

Layout (host path, path inside the container):

| Host | Container | Content |
|---|---|---|
| `$WORK/saguaro` | `/root/saguaro` | Saguaro checkout |
| `$WORK/sev-tools` | `/root/sev-tools` | this repository, the QEMU installation, the guest files |

1. Create the workspace and clone both repositories. `sev-tools` must exist before the container is created.

```bash
export WORK=$HOME/saguaro-sev-emu
mkdir -p "$WORK/sev-tools"
git clone --branch dev-sev https://github.com/adilahmad17/qemu-sev-tcg.git "$WORK/sev-tools/qemu-sev-tcg"
git clone --branch main https://github.com/ASTERISC-Release/saguaro.git "$WORK/saguaro"
```

2. Create the container (the image is built on first use). The output ends with a line containing `Ubuntu 24.04`.

```bash
cd "$WORK/saguaro"
container/run.sh 'grep PRETTY_NAME /etc/os-release'
```

3. Build and install the emulating QEMU into `sev-tools/qemu-emu` (about two minutes). It ends with
   `>>> done: QEMU 11.1.2` and the path `/root/sev-tools/qemu-emu/bin/qemu-system-x86_64`. The binary stays in this
   directory; it finds its ROMs in `../share/qemu`.

```bash
cd "$WORK/saguaro"
container/run.sh 'cd /root/sev-tools/qemu-sev-tcg && ./build.sh --install-deps --prefix /root/sev-tools/qemu-emu'
```

4. Fetch the kernel, build the initrd and fetch OVMF. The script takes one operand per invocation. The files are
   `sev-tools/guest/vmlinuz`, `sev-tools/guest/smoke-initrd.cpio` and
   `sev-tools/firmware/edk2-2025.11/OVMF.fd`. The `guest` invocation ends with the line
   `/root/sev-tools/guest/smoke-initrd.cpio`; the `firmware` invocation prints the SHA-256 values of the OVMF images.

```bash
cd "$WORK/saguaro"
container/run.sh 'cd /root/saguaro && container/sev/build-sev-tools.sh guest'
container/run.sh 'cd /root/saguaro && container/sev/build-sev-tools.sh firmware'
```

5. Boot the guest as an SEV guest (policy 0x1). The guest powers off by itself after a few seconds; `timeout` ends
   QEMU after 300 seconds if it does not. The command prints the kernel line
   `Memory Encryption Features active: AMD SEV` and ends with `SMOKE: done`.

```bash
cd "$WORK/saguaro"
container/run.sh 'cd /root/sev-tools && timeout 300 qemu-emu/bin/qemu-system-x86_64 \
    -accel tcg -cpu max -M q35 -smp 2 -m 2G \
    -object sev-emu,id=sev0,cbitpos=51,reduced-phys-bits=1,policy=0x1 \
    -machine confidential-guest-support=sev0 \
    -bios firmware/edk2-2025.11/OVMF.fd -kernel guest/vmlinuz -initrd guest/smoke-initrd.cpio \
    -append "console=ttyS0" -nographic -net none' | tr -d '\r' | grep -a -E 'Memory Encryption Features active|SMOKE: done'
```

6. Boot the guest as an SEV-ES guest (policy 0x5). The command prints the kernel line
   `Memory Encryption Features active: AMD SEV SEV-ES` and ends with `SMOKE: done`.

```bash
cd "$WORK/saguaro"
container/run.sh 'cd /root/sev-tools && timeout 300 qemu-emu/bin/qemu-system-x86_64 \
    -accel tcg -cpu max -M q35 -smp 2 -m 2G \
    -object sev-emu,id=sev0,cbitpos=51,reduced-phys-bits=1,policy=0x5 \
    -machine confidential-guest-support=sev0 \
    -bios firmware/edk2-2025.11/OVMF.fd -kernel guest/vmlinuz -initrd guest/smoke-initrd.cpio \
    -append "console=ttyS0" -nographic -net none' | tr -d '\r' | grep -a -E 'Memory Encryption Features active|SMOKE: done'
```

7. Boot the guest as an SEV-SNP guest (`sev-snp-emu`, policy 0x30000). The command prints the kernel line
   `Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP` and ends with `SMOKE: done`.

```bash
cd "$WORK/saguaro"
container/run.sh 'cd /root/sev-tools && timeout 300 qemu-emu/bin/qemu-system-x86_64 \
    -accel tcg -cpu max -M q35 -smp 2 -m 2G \
    -object sev-snp-emu,id=sev0,cbitpos=51,reduced-phys-bits=1,policy=0x30000 \
    -machine confidential-guest-support=sev0 \
    -bios firmware/edk2-2025.11/OVMF.fd -kernel guest/vmlinuz -initrd guest/smoke-initrd.cpio \
    -append "console=ttyS0" -nographic -net none' | tr -d '\r' | grep -a -E 'Memory Encryption Features active|SMOKE: done'
```

## Running Saguaro

Steps 1 to 3 of "Running a Linux guest" (workspace, container, QEMU) are the prerequisites; the kernel, initrd and
OVMF of step 4 are not used. Every command runs inside the container from `/root/saguaro` as root.

1. Build and install Saguaro with the SEV PAL (under a minute). The prefix is `/root/.local/saguaro-vm` in the
   container, and `container/run.sh` loads `/root/.local/saguaro-vm/env.sh` (which puts `saguaro-sev` and the
   other tools on `PATH`) in every command. In an interactive shell opened with `container/run.sh` the same applies;
   elsewhere run `. /root/.local/saguaro-vm/env.sh`. The output ends with `Done. To use this install in the
   current shell`.

```bash
cd "$WORK/saguaro"
container/run.sh 'cd /root/saguaro && scripts/install.sh --sev --graphics disabled'
```

2. Run the Hello World example under SEV-SNP. `SAGUARO_ACCEL=tcg` selects the emulation and `QEMU_PATH` the
   emulating QEMU of step 3 (absolute path in the container). The first run builds the example. The output contains
   `Hello, world` and ends with `[PASS] helloworld sev-snp x86_64`.

```bash
cd "$WORK/saguaro"
container/run.sh 'cd /root/saguaro && export SAGUARO_ACCEL=tcg QEMU_PATH=/root/sev-tools/qemu-emu/bin/qemu-system-x86_64 && CI-Examples/helloworld/exec.sh --sev-snp'
```

3. Run it under plain SEV. The output contains `Hello, world` and ends with `[PASS] helloworld sev x86_64`.

```bash
cd "$WORK/saguaro"
container/run.sh 'cd /root/saguaro && export SAGUARO_ACCEL=tcg QEMU_PATH=/root/sev-tools/qemu-emu/bin/qemu-system-x86_64 && CI-Examples/helloworld/exec.sh --sev'
```

4. Run the smoke tier of the regression set (under a minute). The last line reads
   `QUICK variant=sev-emu arch=x86_64 tier=smoke ... status=PASS`.

```bash
cd "$WORK/saguaro"
container/run.sh 'cd /root/saguaro && export SAGUARO_ACCEL=tcg QEMU_PATH=/root/sev-tools/qemu-emu/bin/qemu-system-x86_64 && test/quick.sh sev-snp --tier smoke'
```

`CI-Examples/<name>/exec.sh` and `test/sev/test-sev.sh` accept the same two variables. Saguaro's GitHub workflow `sev-emulated-x86_64.yml` builds this fork and runs the regression tier nightly.

## Tests

The check-tcg guests under `tests/tcg/x86_64/system/` exercise the emulated protocols and instructions:

    make -C build/tests/tcg/x86_64-softmmu run-sev-es run-sev-es-term run-sev-snp run-xsavec

## Credits and license

The `sev-emulated` object, the MSR and C-bit handling, the launch state machine and the launch measurement derive from the RFC "TCG-emulated AMD SEV" by Tommaso Califano (qemu-devel, March 2026); the commits retain his authorship. The remaining changes are by the ASTERISC Research Lab. QEMU is licensed under GPL-2.0-or-later (`COPYING`).
