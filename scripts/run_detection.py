#!/usr/bin/env python3
"""Phase 2: run every vulnerability program under every defense configuration
and classify what happened.  Each (program, configuration) pair is repeated
because MTE (random tags) and ASan quarantine reuse are non-deterministic.

Output: results/detection_runs.csv (one row per run) and
        results/detection_summary.csv (one row per program x configuration).
"""
import argparse
import bisect
import csv
import re
import subprocess
from collections import Counter, defaultdict
from functools import lru_cache

from common import CONFIGS, RESULTS, ROOT, SYSROOT, command, run

SUITE = ["stack_overflow", "heap_overflow", "oob_read", "oob_write", "use_after_free", "double_free"]
BOUNDARY = ["intra_granule_overflow", "far_oob_into_live_object", "uaf_after_reallocation",
            "intra_object_overflow"]

# uaf_after_reallocation needs >256 MiB of churn to flush ASan's quarantine;
# glibc reuses the chunk immediately, so a small value suffices elsewhere.
ARGS = {("uaf_after_reallocation", "asan"): ["320"], ("uaf_after_reallocation", None): ["8"]}

ABORT_PATTERNS = [
    (r"\*\*\* stack smashing detected \*\*\*", "stack canary (__stack_chk_fail)"),
    (r"\*\*\* buffer overflow detected \*\*\*", "FORTIFY_SOURCE (__chk)"),
    (r"(free\(\): double free detected[^\n]*)", "glibc allocator: {0}"),
    (r"(free\(\): invalid [^\n]*)", "glibc allocator: {0}"),
    (r"(malloc\(\)[^\n]*)", "glibc allocator: {0}"),
    (r"(corrupted [^\n]*)", "glibc allocator: {0}"),
    (r"(munmap_chunk\(\)[^\n]*)", "glibc allocator: {0}"),
]


@lru_cache(maxsize=None)
def symbols(path):
    nm = "aarch64-linux-gnu-nm" if "aarch64" in path or str(SYSROOT) in path else "nm"
    try:
        out = subprocess.run([nm, "-D", "--defined-only", path], capture_output=True, text=True).stdout
        out += subprocess.run([nm, "--defined-only", path], capture_output=True, text=True).stdout
    except FileNotFoundError:
        return [], []
    syms = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1].lower() in "tw":
            syms.append((int(parts[0], 16), parts[2].split("@")[0]))
    syms.sort()
    return [a for a, _ in syms], [n for _, n in syms]


def locate(module, pc_off, binary):
    """Map a faulting PC to 'file:line (function)' or 'libc:function'."""
    if module.startswith("build/") or module == str(binary) or module.endswith(binary.name):
        addr2line = "aarch64-linux-gnu-addr2line" if "aarch64" in str(binary) else "addr2line"
        r = subprocess.run([addr2line, "-f", "-s", "-e", str(binary), pc_off],
                           capture_output=True, text=True).stdout.split("\n")
        if len(r) >= 2 and "??" not in r[1]:
            return f"{r[1].split(' ')[0]} ({r[0]})"
        # Not in user code (e.g. a PLT stub): name the enclosing objdump symbol.
        objdump = "aarch64-linux-gnu-objdump" if "aarch64" in str(binary) else "objdump"
        dis = subprocess.run([objdump, "-d", str(binary)], capture_output=True, text=True).stdout
        starts = sorted((int(a, 16), n) for a, n in re.findall(r"^([0-9a-f]+) <([^>]+)>:", dis, re.M))
        i = bisect.bisect_right([a for a, _ in starts], int(pc_off, 16)) - 1
        return f"{binary.name}:{starts[i][1]}" if i >= 0 else f"{binary.name}+{pc_off}"
    lib = module
    if module.startswith("/lib") and SYSROOT.exists():
        lib = str(SYSROOT) + module.replace("/lib/", "/lib/aarch64-linux-gnu/", 1) \
            if not module.startswith("/lib/aarch64") else str(SYSROOT) + module
    addrs, names = symbols(lib)
    off = int(pc_off, 16)
    i = bisect.bisect_right(addrs, off) - 1
    fn = names[i] if i >= 0 else "?"
    return f"{module.rsplit('/', 1)[-1]}:{fn}"


def classify(rc, out, err, binary):
    """Return (outcome, mechanism, location, continued_past_bug)."""
    text = out + err
    continued = "Done." in out
    hijacked = "CONTROL FLOW HIJACKED" in out
    m = re.search(r"ERROR: AddressSanitizer: (.+?) on ", err)
    if m:
        loc = re.search(r"SUMMARY: AddressSanitizer: [\w-]+ (\S+)", err)
        return "DETECTED", f"ASan: {m.group(1)}", loc.group(1).rsplit("/", 1)[-1] if loc else "", continued
    f = re.search(r"\[FAULT\] sig=(\w+) code=(\d+)\((\w+)\) addr=(\S+) pc_off=(\S+) module=(\S+)", err)
    if f and f.group(3) in ("SEGV_MTESERR", "SEGV_MTEAERR"):
        kind = "MTE sync tag-check fault (precise)" if f.group(3) == "SEGV_MTESERR" \
            else "MTE async tag-check fault (imprecise, addr=0)"
        return "DETECTED", kind, locate(f.group(6), f.group(5), binary), continued
    for pat, label in ABORT_PATTERNS:
        a = re.search(pat, text)
        if a:
            return "DETECTED", label.format(*a.groups()), "", continued
    if f and f.group(1) in ("TRAP", "ILL"):
        return "DETECTED", "bounds-check trap (-fsanitize=bounds-strict)", locate(f.group(6), f.group(5), binary), continued
    if f and f.group(1) == "SEGV":
        where = locate(f.group(6), f.group(5), binary)
        return "CRASH", f"segfault {f.group(3)} (side effect, not a defense)", "" if "?" in where else where, continued
    if rc == 0 and (continued or hijacked):
        return "MISSED", "control-flow hijacked" if hijacked else "silent corruption", "", continued
    return "OTHER", f"rc={rc}", "", continued


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=20)
    a = ap.parse_args()
    RESULTS.mkdir(exist_ok=True)
    rows = []
    for plat, cfgs in CONFIGS.items():
        for prog in SUITE + BOUNDARY:
            for cfg in cfgs:
                args = ARGS.get((prog, cfg), ARGS.get((prog, None), []))
                cmd, env, binary = command(plat, cfg, prog, args)
                for rep in range(a.reps):
                    rc, out, err = run(cmd, env)
                    outcome, mech, loc, cont = classify(rc, out, err, binary)
                    extra = ""
                    if prog == "uaf_after_reallocation":
                        m = re.search(r"reused by live object: (\w+)", out)
                        extra = f"chunk_reused={m.group(1)}" if m else ""
                    rows.append(dict(platform=plat, program=prog, set="suite" if prog in SUITE else "boundary",
                                     config=cfg, rep=rep, returncode=rc, outcome=outcome, mechanism=mech,
                                     location=loc, continued_past_bug=cont, note=extra))
                print(f"{plat:8} {prog:26} {cfg:10} -> {rows[-1]['outcome']:9} {rows[-1]['mechanism']} {rows[-1]['location']}")

    with open(RESULTS / "detection_runs.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    groups = defaultdict(list)
    for r in rows:
        groups[(r["platform"], r["program"], r["set"], r["config"])].append(r)
    with open(RESULTS / "detection_summary.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["platform", "program", "set", "config", "runs", "detected", "detection_rate",
                    "mechanisms", "locations", "continued_past_bug", "notes"])
        for (plat, prog, st, cfg), rs in groups.items():
            det = sum(r["outcome"] == "DETECTED" for r in rs)
            mech = Counter(r["mechanism"] for r in rs)
            locs = Counter(r["location"] for r in rs if r["location"])
            notes = Counter(r["note"] for r in rs if r["note"])
            w.writerow([plat, prog, st, cfg, len(rs), det, f"{det / len(rs):.2f}",
                        "; ".join(f"{k} x{v}" for k, v in mech.most_common()),
                        "; ".join(f"{k} x{v}" for k, v in locs.most_common()),
                        sum(bool(r["continued_past_bug"]) for r in rs),
                        "; ".join(f"{k} x{v}" for k, v in notes.most_common())])
    print("wrote", RESULTS / "detection_summary.csv")


if __name__ == "__main__":
    main()
