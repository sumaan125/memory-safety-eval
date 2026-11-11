#!/usr/bin/env bash
# Build every program in every defense configuration.
#
#   build/<arch>/<config>/<program>
#
#   arch   : x86_64 (native gcc) | aarch64 (aarch64-linux-gnu-gcc, run under
#            qemu-aarch64 -cpu max, or natively on an MTE-capable ARM board)
#   config : baseline | hardening | asan
#
# MTE-sync / MTE-async need no separate build: they run the *baseline*
# aarch64 binary with glibc heap tagging switched on at load time
# (GLIBC_TUNABLES=glibc.mem.tagging=3 / =1), the same mechanism used by
# Noh et al. Only the run-time environment differs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

declare -A CC=([x86_64]=gcc [aarch64]=aarch64-linux-gnu-gcc)
# If we are already on an AArch64 host, build natively.
if [ "$(uname -m)" = "aarch64" ]; then CC[aarch64]=gcc; fi

# Ubuntu's GCC enables some hardening by default, so the baseline turns it
# off explicitly.
BASE_OFF="-fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-stack-clash-protection"
declare -A CFG=(
  [baseline]="$BASE_OFF"
  [hardening]="-fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fsanitize=bounds-strict -fsanitize-trap=all"
  [asan]="-fsanitize=address -fno-omit-frame-pointer"
)
X86_EXTRA="-fcf-protection=none"   # keep CET out of the x86 baseline as well

# Vulnerability programs are compiled at -O0: at -O1 and above GCC treats the
# undefined behaviour as dead code and deletes the faulty accesses (see the
# report, Section 4.1). Benchmarks use -O2.
# -std=gnu17 avoids C23 symbol versions (GLIBC_2.38) so the AArch64
# binaries also run against the glibc 2.36 sysroot used for MTE.
SUITE_OPT="-std=gnu17 -O0 -g"
BENCH_OPT="-std=gnu17 -O2 -g"

build_one() { # arch config src out opt
  local arch=$1 cfg=$2 src=$3 out=$4 opt=$5 extra=""
  [ "$arch" = x86_64 ] && extra="$X86_EXTRA"
  mkdir -p "$(dirname "$out")"
  # shellcheck disable=SC2086
  ${CC[$arch]} $opt ${CFG[$cfg]} $extra -w -o "$out" "$src" harness/fault_reporter.c
}

for arch in x86_64 aarch64; do
  for cfg in baseline hardening asan; do
    # ASan cannot run under QEMU user-mode (shadow memory mapping fails), so
    # the AArch64 ASan build is only produced on a native AArch64 host.
    if [ "$arch" = aarch64 ] && [ "$cfg" = asan ] && [ "$(uname -m)" != aarch64 ]; then continue; fi
    for src in suit/*.c boundary/*.c; do
      build_one "$arch" "$cfg" "$src" "build/$arch/$cfg/$(basename "$src" .c)" "$SUITE_OPT"
    done
    for src in bench/*.c; do
      build_one "$arch" "$cfg" "$src" "build/$arch/$cfg/$(basename "$src" .c)" "$BENCH_OPT"
    done
  done
done

# Phase-4 / mode experiments: AArch64 only, plain build (tagging via tunable).
for src in experiments/*.c; do
  mkdir -p build/aarch64/experiments
  ${CC[aarch64]} -std=gnu17 -O1 -g -w -o "build/aarch64/experiments/$(basename "$src" .c)" "$src"
done
echo "build complete: $(find build -type f | wc -l) binaries"
