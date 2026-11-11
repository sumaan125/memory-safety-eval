#!/usr/bin/env python3
"""Phase 3: runtime and peak memory of the benchmarks in every configuration.

Each (platform, workload, configuration) is run --reps times; the median wall
time and median max-RSS are reported.  Overheads are normalised to the
baseline configuration of the same platform.

Workload sizes differ per platform (QEMU is ~10-100x slower than native),
which is fine because results are only compared within a platform.

Output: results/perf_runs.csv, results/perf_summary.csv
"""
import argparse
import csv
import statistics
from collections import defaultdict

from common import CONFIGS, RESULTS, command, run_measured

# name -> (program, x86 args, aarch64-under-QEMU args)
WORKLOADS = {
    "alloc-small":  ("bench_alloc", [16, 256, 30_000_000], [16, 256, 3_000_000]),
    "alloc-medium": ("bench_alloc", [1024, 4096, 10_000_000], [1024, 4096, 1_000_000]),
    "alloc-large":  ("bench_alloc", [32768, 131072, 1_000_000], [32768, 131072, 50_000]),
    "access-seq":   ("bench_access", ["seq", 64, 50], ["seq", 64, 5]),
    "access-rand":  ("bench_access", ["rand", 32, 20_000_000], ["rand", 32, 5_000_000]),
    "kv-store":     ("bench_kv", [5_000_000, 100_000], [1_000_000, 100_000]),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--platform", choices=list(CONFIGS), action="append")
    a = ap.parse_args()
    plats = a.platform or list(CONFIGS)
    RESULTS.mkdir(exist_ok=True)
    rows = []
    for plat in plats:
        for wl, (prog, x86_args, arm_args) in WORKLOADS.items():
            args = x86_args if plat == "x86_64" else arm_args
            for cfg in CONFIGS[plat]:
                cmd, env, _ = command(plat, cfg, prog, args)
                run_measured(cmd, env)  # warm-up (page cache, CPU frequency)
                for rep in range(a.reps):
                    rc, wall, rss = run_measured(cmd, env)
                    if rc != 0:
                        raise SystemExit(f"benchmark failed rc={rc}: {' '.join(cmd)}")
                    rows.append(dict(platform=plat, workload=wl, config=cfg, rep=rep,
                                     wall_s=f"{wall:.4f}", maxrss_kib=rss))
                med = statistics.median(float(r["wall_s"]) for r in rows[-a.reps:])
                print(f"{plat:8} {wl:13} {cfg:10} median {med:8.3f}s rss {rows[-1]['maxrss_kib']} KiB", flush=True)

    with open(RESULTS / "perf_runs.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    g = defaultdict(list)
    for r in rows:
        g[(r["platform"], r["workload"], r["config"])].append(r)
    med = {k: (statistics.median(float(r["wall_s"]) for r in v),
               statistics.median(int(r["maxrss_kib"]) for r in v),
               statistics.stdev(float(r["wall_s"]) for r in v) if len(v) > 1 else 0.0)
           for k, v in g.items()}
    with open(RESULTS / "perf_summary.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["platform", "workload", "config", "median_wall_s", "stdev_wall_s", "median_maxrss_kib",
                    "slowdown_vs_baseline", "rss_vs_baseline"])
        for (plat, wl, cfg), (t, rss, sd) in med.items():
            bt, brss, _ = med[(plat, wl, "baseline")]
            w.writerow([plat, wl, cfg, f"{t:.4f}", f"{sd:.4f}", rss, f"{t / bt:.3f}", f"{rss / brss:.3f}"])
    print("wrote", RESULTS / "perf_summary.csv")


if __name__ == "__main__":
    main()
