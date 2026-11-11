#!/usr/bin/env bash
# Reproduce every result, figure and table of the project.
set -euo pipefail
cd "$(dirname "$0")"
scripts/build.sh
python3 scripts/run_detection.py --reps 20      # Phase 2: detection matrix
python3 scripts/run_mte_experiments.py           # Phase 4 + RQ3: tag space, sync/async
python3 scripts/run_perf.py --reps 5             # Phase 3: runtime / memory
python3 scripts/run_perf_counters.py --reps 5    # Phase 3: perf stat counters (x86-64)
python3 scripts/make_figures.py                  # figures/ and results/tables.tex
