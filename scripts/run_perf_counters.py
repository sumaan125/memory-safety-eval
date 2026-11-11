#!/usr/bin/env python3
"""Phase 3 (perf): hardware/software counters with `perf stat` for each benchmark.

Only the native x86-64 configurations are profiled.  Under QEMU user-mode the
counters would measure the emulator's translated code, not the guest program,
so they say nothing about MTE.

Each (workload, configuration) runs as `perf stat -r REPS -x,` after one warm-up;
perf reports the mean over the repetitions.

Output: results/perf_counters.csv
"""
import argparse
import csv
import subprocess

from common import CONFIGS, RESULTS, ROOT, command
from run_perf import WORKLOADS

EVENTS = ["task-clock", "cycles", "instructions", "cache-references", "cache-misses",
          "branch-misses", "page-faults"]


def perf_stat(cmd, env, reps):
    full = ["perf", "stat", "-r", str(reps), "-x,", "-e", ",".join(EVENTS), "--"] + cmd
    p = subprocess.run(full, env=env, cwd=ROOT, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise SystemExit(f"perf failed rc={p.returncode}: {p.stderr}")
    vals = {}
    for line in p.stderr.splitlines():
        f = line.split(",")
        if len(f) < 3:
            continue
        name = f[2].split(":")[0]
        if name in EVENTS:
            if f[0].startswith("<"):
                raise SystemExit(f"event {name} not counted: {line}")
            vals[name] = float(f[0])
    return vals


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=5)
    a = ap.parse_args()
    rows = []
    for wl, (prog, x86_args, _) in WORKLOADS.items():
        for cfg in CONFIGS["x86_64"]:
            cmd, env, _ = command("x86_64", cfg, prog, x86_args)
            subprocess.run(cmd, env=env, cwd=ROOT, stdout=subprocess.DEVNULL)  # warm-up
            v = perf_stat(cmd, env, a.reps)
            v["ipc"] = v["instructions"] / v["cycles"]
            v["cache_miss_rate"] = v["cache-misses"] / v["cache-references"]
            rows.append(dict(workload=wl, config=cfg, **v))
            print(f"{wl:13} {cfg:10} cycles {v['cycles']:.3e} instr {v['instructions']:.3e} "
                  f"IPC {v['ipc']:.2f} cache-miss {v['cache-misses']:.3e} pf {v['page-faults']:.0f}",
                  flush=True)
    with open(RESULTS / "perf_counters.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print("wrote", RESULTS / "perf_counters.csv")


if __name__ == "__main__":
    main()
