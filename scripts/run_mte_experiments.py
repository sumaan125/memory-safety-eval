#!/usr/bin/env python3
"""Phase 4 (tag space) and RQ3 (sync vs async reporting) experiments.

Output:
  results/tag_space_<section>.csv   one file per experiment section
  results/mode_probe.csv            sync/async reporting behaviour
"""
import argparse
import csv
import os
import re

from common import BUILD, RESULTS, arm_prefix, run


def run_tag_space(trials):
    env = dict(os.environ, GLIBC_TUNABLES="glibc.mem.tagging=3")  # SYNC: precise, catchable
    cmd = arm_prefix() + [str(BUILD / "aarch64/experiments/mte_tag_space"), str(trials)]
    rc, out, err = run(cmd, env, timeout=3600)
    if rc != 0:
        raise SystemExit(f"mte_tag_space failed rc={rc}\n{err}")
    sections, cur = {}, None
    for line in out.splitlines():
        if line.startswith("#section"):
            cur = line.split()[1]
            sections[cur] = []
        elif line.startswith("#info"):
            print(line)
        elif cur:
            sections[cur].append(line)
    for name, lines in sections.items():
        (RESULTS / f"tag_space_{name}.csv").write_text("\n".join(lines) + "\n")
        print(f"tag_space_{name}.csv: {len(lines) - 1} rows")


def run_mode_probe(reps):
    rows = []
    for mode in ("write", "read"):
        for cfg, tun in (("mte-sync", 3), ("mte-async", 1)):
            env = dict(os.environ, GLIBC_TUNABLES=f"glibc.mem.tagging={tun}")
            cmd = arm_prefix() + [str(BUILD / "aarch64/experiments/mte_mode_probe"), mode]
            for rep in range(reps):
                rc, out, err = run(cmd, env)
                m = re.search(r"RESULT (.*)", out)
                kv = dict(re.findall(r"(\w+)=(\S+)", m.group(1))) if m else {}
                rows.append(dict(access=mode, config=cfg, rep=rep,
                                 si_code=kv.get("si_code", ""),
                                 fault_addr=kv.get("fault_addr", ""),
                                 progress_after_bug=kv.get("progress_after_bug", "").split("/")[0],
                                 illegal_store_committed=kv.get("secret_first_byte", "") == "!",
                                 bytes_leaked=kv.get("bytes_leaked", ""),
                                 raw=m.group(1) if m else out.strip()[-200:]))
            print(rows[-1])
    with open(RESULTS / "mode_probe.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=2000)
    ap.add_argument("--reps", type=int, default=10)
    a = ap.parse_args()
    RESULTS.mkdir(exist_ok=True)
    run_mode_probe(a.reps)
    run_tag_space(a.trials)


if __name__ == "__main__":
    main()
