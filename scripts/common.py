"""Shared helpers: platforms, configurations and process execution."""
import os
import platform
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
RESULTS = ROOT / "results"
FIGURES = ROOT / "figures"
SYSROOT = ROOT / "sysroot-glibc2.36"   # glibc 2.36 (same version as Noh et al.)

NATIVE_ARM = platform.machine() == "aarch64"


def arm_prefix():
    """Command prefix for running an AArch64 binary.

    On an x86-64 host the binary runs under QEMU user-mode with an
    MTE-capable CPU model; on an AArch64 (MTE hardware) host it runs natively.
    """
    if NATIVE_ARM:
        return []
    return ["qemu-aarch64", "-cpu", "max", "-L", str(SYSROOT)]


# name -> (arch, build-config dir, extra environment)
CONFIGS = {
    "x86_64": {
        "baseline":  ("x86_64", "baseline", {}),
        "hardening": ("x86_64", "hardening", {}),
        "asan":      ("x86_64", "asan", {"ASAN_OPTIONS": "detect_leaks=0"}),
    },
    "aarch64": {
        "baseline":  ("aarch64", "baseline", {"GLIBC_TUNABLES": "glibc.mem.tagging=0"}),
        "hardening": ("aarch64", "hardening", {"GLIBC_TUNABLES": "glibc.mem.tagging=0"}),
        # MTE runs the unmodified baseline binary; glibc enables heap tagging
        # at start-up. Bit 0 = enable tagging, bit 1 = precise (SYNC) faults.
        "mte-sync":  ("aarch64", "baseline", {"GLIBC_TUNABLES": "glibc.mem.tagging=3"}),
        "mte-async": ("aarch64", "baseline", {"GLIBC_TUNABLES": "glibc.mem.tagging=1"}),
    },
}
if NATIVE_ARM:  # ASan is runnable on real AArch64 hardware
    CONFIGS["aarch64"]["asan"] = ("aarch64", "asan", {"ASAN_OPTIONS": "detect_leaks=0"})

PLATFORM_LABEL = {
    "x86_64": "x86-64 native (AMD Ryzen 5 5600H)",
    "aarch64": "AArch64 MTE (native)" if NATIVE_ARM else "AArch64 + MTE under QEMU 10.2 user-mode (-cpu max)",
}


def command(platform_name, config, program, args=()):
    arch, cfgdir, env = CONFIGS[platform_name][config]
    binary = BUILD / arch / cfgdir / program
    prefix = arm_prefix() if arch == "aarch64" else []
    full_env = dict(os.environ)
    full_env.pop("GLIBC_TUNABLES", None)
    full_env.update(env)
    return prefix + [str(binary), *map(str, args)], full_env, binary


def run(cmd, env, timeout=600):
    """Run a command; return (returncode, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, env=env, capture_output=True, cwd=ROOT, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        return -999, (e.stdout or b"").decode(errors="replace"), (e.stderr or b"").decode(errors="replace")
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


def run_measured(cmd, env):
    """Run a benchmark; return (exitcode, wall_seconds, max_rss_kib).

    os.wait4 gives the resource usage of exactly this child (under QEMU the
    RSS includes the emulator itself, which is a constant offset).
    """
    t0 = time.perf_counter()
    p = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=ROOT)
    _, status, ru = os.wait4(p.pid, 0)
    wall = time.perf_counter() - t0
    p.returncode = os.waitstatus_to_exitcode(status)
    return p.returncode, wall, ru.ru_maxrss
