#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# libnx targets aarch64 Horizon (devkitA64 + newlib); there is no host build upstream. The
# harnesses compile the parsing sources unmodified for the host, against small shims for the
# newlib headers devkitA64 provides (mayhem/shim) and stand-ins for the Horizon IPC calls that
# sit at the edge of each parser (in each harness). Everything lands in mayhem/out (gitignored).
OUT="$SRC/mayhem/out"
GEN="$OUT/gen"
mkdir -p "$OUT/fuzz" "$OUT/test" "$GEN"
python3 mayhem/gen_font.py nx/data/default_font.bin "$GEN/default_font_bin.h"

# -funsigned-char: libnx is AArch64 code, where plain char is unsigned (on x86_64 it is signed,
# which would turn correct code such as inet_addr.c's char octets into host-only bugs).
INC="-funsigned-char -I$GEN -I$SRC/mayhem/shim -I$SRC/nx/include -I$SRC/nx/include/switch -I$SRC/nx/source -D__SWITCH__"
# libnx's inet_* are renamed so they don't interpose glibc's (see mayhem/shim/nx_inet_host.h).
INET="-include $SRC/mayhem/shim/nx_inet_host.h -Dinet_pton=nx_inet_pton -Dinet_ntop=nx_inet_ntop -Dinet_aton=nx_inet_aton -Dinet_addr=nx_inet_addr -Dinet_ntoa=nx_inet_ntoa -Din6addr_loopback=nx_in6addr_loopback -Din6addr_any=nx_in6addr_any"
# RomFS packs its u64-bearing entries on 4-byte boundaries (fine on aarch64), so every valid
# image trips UBSan's alignment check; relax only that check, only on romfs_dev.c.
ROMFS_RELAX="-fno-sanitize=alignment"
# fuzz_hidbus.c includes hidbus.c (plus libnx's inline IPC layer, sf/service.h). Every
# serviceDispatch computes &out_handles[i] on a NULL array, which UBSan's pointer-overflow check
# reports on every call; relax only that check, only on that TU.
HIDBUS_RELAX="-fno-sanitize=pointer-overflow"

# compile <outdir> <flags> <src> [extra flags] -> prints the object path
obj() {
  local dir="$1" flags="$2" src="$3"; shift 3
  local o="$dir/$(echo "${src#$SRC/}" | tr '/' '_').o"
  # shellcheck disable=SC2086
  $CC $flags $INC "$@" -c "$src" -o "$o"
  echo "$o"
}

# -fsanitize=fuzzer-no-link: SanCov on every fuzz object (libnx sources AND harnesses), unconditionally,
# so libFuzzer/Mayhem get coverage feedback; $LIB_FUZZING_ENGINE only adds the runtime at link time.
FZ="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
L="$OUT/fuzz"
LSAN=$(obj "$L" "$FZ" "$SRC/mayhem/lsan_off.c")
UTF=""; for f in nx/source/runtime/util/utf/*.c; do UTF="$UTF $(obj "$L" "$FZ" "$SRC/$f")"; done
ROMFS="$(obj "$L" "$FZ" "$SRC/nx/source/runtime/devices/romfs_dev.c" $ROMFS_RELAX) $(obj "$L" "$FZ" "$SRC/nx/source/runtime/devices/path_buf.c")"
CONSW=$(obj "$L" "$FZ" "$SRC/nx/source/runtime/devices/console_sw.c")
INETO=$(obj "$L" "$FZ" "$SRC/nx/source/runtime/util/inet_addr.c" $INET)
PARCEL=$(obj "$L" "$FZ" "$SRC/nx/source/display/parcel.c")
ARGV="$(obj "$L" "$FZ" "$SRC/nx/source/runtime/argv.c") $(obj "$L" "$FZ" "$SRC/nx/source/runtime/nxlink.c")"

declare -A LIBS=(
  [romfs]="$ROMFS"
  [console]="$CONSW"
  [utf]="$UTF"
  [inet]="$INETO"
  [parcel]="$PARCEL"
  [argv]="$ARGV"
  [hidbus]=""
)
declare -A HFLAGS=( [hidbus]="$HIDBUS_RELAX" )
for t in romfs console utf inet parcel argv hidbus; do
  # shellcheck disable=SC2086
  h=$(obj "$L" "$FZ" "$SRC/mayhem/harnesses/fuzz_$t.c" ${HFLAGS[$t]:-})
  # shellcheck disable=SC2086
  $CC $FZ $LIB_FUZZING_ENGINE "$h" ${LIBS[$t]} "$LSAN" -o "/mayhem/fuzz_$t"
  # shellcheck disable=SC2086
  $CC $FZ "$STANDALONE_FUZZ_MAIN" "$h" ${LIBS[$t]} "$LSAN" -o "/mayhem/fuzz_$t-standalone"
done

# Functional oracle: known-answer self-test of the same libnx sources, NORMAL flags, no sanitizers.
T="$OUT/test"
TF="-O1 $COVERAGE_FLAGS"
TOBJ=""
for f in nx/source/runtime/util/utf/*.c nx/source/runtime/devices/romfs_dev.c nx/source/runtime/devices/path_buf.c \
         nx/source/runtime/devices/console_sw.c nx/source/display/parcel.c nx/source/runtime/argv.c nx/source/runtime/nxlink.c; do
  TOBJ="$TOBJ $(obj "$T" "$TF" "$SRC/$f")"
done
TOBJ="$TOBJ $(obj "$T" "$TF" "$SRC/nx/source/runtime/util/inet_addr.c" $INET)"
# shellcheck disable=SC2086
$CC $TF $INC $TOBJ "$SRC/mayhem/selftest.c" -o "$OUT/libnx_selftest"
echo "build.sh: done"
