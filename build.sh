#!/usr/bin/env bash
# build.sh -- build the QEMU with the emulated AMD SEV / SEV-ES / SEV-SNP (branch dev-sev)
#
# The emulation is functional only (no attestation, no memory isolation) and runs under TCG, so the
# build has no KVM. It needs libigvm, which is built first from a pinned release. Everything goes to
# one prefix: bin/qemu-system-x86_64 and share/qemu (the ROMs and firmware QEMU looks for next to the
# binary, which is why the binary must stay where it was installed).
#
#   ./build.sh [--prefix DIR] [--jobs N] [--install-deps] [--clean]
#
#   --prefix DIR     install prefix (default: <this directory>/prefix)
#   --jobs N         parallel jobs (default: all CPUs)
#   --install-deps   install the Ubuntu/Debian packages the build needs first (apt-get, sudo unless root)
#   --clean          remove the build directory and the downloaded libigvm first
#
# Needs: a C toolchain, git (QEMU fetches a small subproject), ninja, python3 with venv, pkg-config, the glib/pixman/slirp/fdt development
# packages, cargo and rustc (for libigvm and cbindgen), curl. When it finishes it checks the result and
# prints how to use it with Saguaro:
#   SAGUARO_ACCEL=tcg QEMU_PATH=<prefix>/bin/qemu-system-x86_64 CI-Examples/helloworld/exec.sh --sev-snp
set -euo pipefail

HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
PREFIX=$HERE/prefix
JOBS=$(nproc)
DEPS=0
CLEAN=0
IGVM_TAG=igvm-v0.4.0
IGVM_SHA256=1ee7b61769254a59de1011ca3fe0b6a17cc8e8412a4f564d77c324a160b4eccf
CBINDGEN_VERSION=0.29.4
APT_PACKAGES="build-essential ninja-build python3 python3-venv pkg-config libglib2.0-dev libpixman-1-dev
              libslirp-dev libfdt-dev flex bison curl ca-certificates git cargo rustc"

while [ $# -gt 0 ]; do
    case $1 in
        --prefix) PREFIX=$(readlink -m "${2:?--prefix needs a directory}"); shift ;;
        --jobs) JOBS=${2:?--jobs needs a number}; shift ;;
        --install-deps) DEPS=1 ;;
        --clean) CLEAN=1 ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) echo "build.sh: unknown argument: $1 (--help)" >&2; exit 2 ;;
    esac
    shift
done

BUILD=$HERE/build
IGVM_DIR=$HERE/build-igvm
log() { echo ">>> $*"; }
die() { echo "build.sh: $*" >&2; exit 1; }

if [ $DEPS = 1 ]; then
    command -v apt-get >/dev/null || die "--install-deps needs apt-get (Ubuntu or Debian)"
    sudo=; [ "$(id -u)" = 0 ] || sudo=sudo
    log "installing packages"
    $sudo apt-get update -qq
    # shellcheck disable=SC2086
    $sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $APT_PACKAGES
    # libigvm's dependencies need rustc 1.77 or newer; Ubuntu 24.04's default rustc is 1.75
    $sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cargo-1.85 rustc-1.85 2>/dev/null || true
fi

missing=
for c in gcc make ninja pkg-config python3 flex bison curl git cargo rustc; do
    command -v "$c" >/dev/null || missing="$missing $c"
done
for p in glib-2.0 pixman-1 slirp; do
    pkg-config --exists "$p" 2>/dev/null || missing="$missing lib:$p"
done
python3 -c 'import venv, ensurepip' 2>/dev/null || missing="$missing python3-venv"
[ -z "$missing" ] || die "missing:$missing (on Ubuntu or Debian: ./build.sh --install-deps)"

# a Rust toolchain of at least 1.80 for libigvm: the one on PATH, else the newest /usr/lib/rust-*
rust_minor() { rustc --version 2>/dev/null | sed -n 's/^rustc 1\.\([0-9]*\)\..*/\1/p'; }
if [ "$(rust_minor || echo 0)" -lt 80 ] 2>/dev/null || [ -z "$(rust_minor)" ]; then
    for d in $(ls -d /usr/lib/rust-1.*/bin 2>/dev/null | sort -t. -k2 -n -r); do
        PATH=$d:$PATH
        [ "$(rust_minor)" -ge 80 ] 2>/dev/null && break
    done
fi
[ "$(rust_minor)" -ge 80 ] 2>/dev/null || die "needs rustc 1.80 or newer for libigvm (found: $(rustc --version 2>&1)); on Ubuntu 24.04: ./build.sh --install-deps installs rustc-1.85, or use rustup"
log "using $(rustc --version)"

[ $CLEAN = 0 ] || { log "cleaning"; rm -rf "$BUILD" "$IGVM_DIR"; }
mkdir -p "$PREFIX"
export PATH=$PREFIX/bin:$PATH

# libigvm, the IGVM loader of QEMU (needs cbindgen)
if [ ! -f "$PREFIX/lib64/pkgconfig/igvm.pc" ]; then
    if ! command -v cbindgen >/dev/null; then
        log "cbindgen $CBINDGEN_VERSION"
        cargo install --locked --root "$PREFIX" --version "$CBINDGEN_VERSION" cbindgen
    fi
    log "libigvm ($IGVM_TAG)"
    rm -rf "$IGVM_DIR"; mkdir -p "$IGVM_DIR"
    curl -sSfL -o "$IGVM_DIR/igvm.tar.gz" "https://github.com/microsoft/igvm/archive/refs/tags/$IGVM_TAG.tar.gz"
    have=$(sha256sum "$IGVM_DIR/igvm.tar.gz" | cut -d' ' -f1)
    [ "$have" = "$IGVM_SHA256" ] || die "libigvm tarball: sha256 $have, expected $IGVM_SHA256"
    tar -xzf "$IGVM_DIR/igvm.tar.gz" -C "$IGVM_DIR" --strip-components=1
    make -C "$IGVM_DIR" -f igvm_c/Makefile RELEASE=1 EXTRA_PARAMS=--release CFLAGS="-O2" build
    ver=$(grep -m1 -oP '(?<=^version = ")[^"]+' "$IGVM_DIR/igvm/Cargo.toml")
    mkdir -p "$PREFIX/include/igvm" "$PREFIX/lib64/pkgconfig"
    install -m 644 "$IGVM_DIR/target_c/release/libigvm.a" "$PREFIX/lib64/"
    install -m 644 "$IGVM_DIR/igvm_c/include/"* "$PREFIX/include/igvm/"
    sed -e "s|\${PREFIX}|$PREFIX|g" -e "s|\$PREFIX|$PREFIX|g" \
        -e "s|\${VERSION}|$ver|g" -e "s|\$VERSION|$ver|g" \
        "$IGVM_DIR/igvm_c/igvm.pc.in" > "$PREFIX/lib64/pkgconfig/igvm.pc"
    log "libigvm $ver installed in $PREFIX"
fi

# QEMU: x86_64 system emulation, TCG only (the emulated SEV refuses KVM), IGVM for the guest image
log "configuring QEMU"
mkdir -p "$BUILD"
cd "$BUILD"
PKG_CONFIG_PATH=$PREFIX/lib64/pkgconfig ../configure --prefix="$PREFIX" \
    --target-list=x86_64-softmmu --disable-kvm --enable-igvm --enable-slirp \
    --disable-docs --disable-werror --disable-xen --disable-gtk --disable-sdl --disable-vnc \
    --disable-opengl --disable-virglrenderer
log "building QEMU ($JOBS jobs)"
make -j"$JOBS"
log "installing into $PREFIX"
make install

# check the result: the binary, the objects, TCG and the ROMs the guest needs
Q=$PREFIX/bin/qemu-system-x86_64
[ -x "$Q" ] || die "$Q was not built"
for rom in bios-256k.bin kvmvapic.bin efi-e1000e.rom; do
    [ -f "$PREFIX/share/qemu/$rom" ] || die "$PREFIX/share/qemu/$rom is missing: the guest could not start"
done
objs=$("$Q" -object help 2>/dev/null)
for t in sev-emu sev-snp-emu igvm-cfg; do
    grep -qx "  $t" <<<"$objs" || die "$Q has no '$t' object: is this the dev-sev branch?"
done
"$Q" -accel help 2>/dev/null | grep -qx tcg || die "$Q has no TCG accelerator"

version=$("$Q" --version | sed -n '1s/^QEMU emulator version //p')
echo
log "done: QEMU $version"
echo "  $Q"
echo
echo "Use it with Saguaro (keep the binary where it is: it finds its ROMs in ../share/qemu):"
echo "  export SAGUARO_ACCEL=tcg QEMU_PATH=$Q"
echo "  CI-Examples/helloworld/exec.sh --sev-snp        # or --sev; test/sev/test-sev.sh; test/quick.sh sev-snp"
