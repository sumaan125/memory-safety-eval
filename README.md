# Understanding Hardware-Assisted Memory Safety
**ARM MTE vs. software sanitization: an experimental study** (E0-256 Computer Systems Security, IISc)

The project is based on Noh et al., *ARM MTE Performance in Practice*, USENIX Security 2026.
It compares five defense configurations on a synthetic vulnerability suite and on small benchmarks.

| Config | How it is obtained | Runs on |
|---|---|---|
| Baseline | `-fno-stack-protector -D_FORTIFY_SOURCE=0` (Ubuntu's default hardening switched off) | x86-64 and AArch64 |
| Compiler hardening | `-fstack-protector-strong -D_FORTIFY_SOURCE=3 -fsanitize=bounds-strict -fsanitize-trap=all` | x86-64 and AArch64 |
| ASan | `-fsanitize=address`, with `ASAN_OPTIONS=detect_leaks=0` | x86-64 only |
| MTE-sync | the **unmodified AArch64 baseline binary**, run with `GLIBC_TUNABLES=glibc.mem.tagging=3` | AArch64 |
| MTE-async | the same binary, run with `GLIBC_TUNABLES=glibc.mem.tagging=1` | AArch64 |

- **No MTE hardware is needed.** AArch64 programs run under QEMU user-mode emulation (`qemu-aarch64 -cpu max`), which implements MTE.
- **x86-64 is still needed.** ASan cannot run under QEMU, and only native x86-64 gives real timings and `perf` counters.
- The AArch64 Baseline and Hardening runs are the controls for MTE; the x86-64 Baseline and Hardening runs are the controls for ASan.

---

## 1. Project layout
```
suit/               Phase 1 vulnerability suite (6 programs)
boundary/           4 boundary cases for RQ2 (where the defenses disagree)
experiments/        mte_tag_space.c (Phase 4), mte_mode_probe.c (RQ3: sync vs async)
bench/              Phase 3 workloads: allocation-heavy, access-heavy, key-value store
harness/            fault_reporter.c, linked into every test; prints signal, si_code and PC
scripts/            build.sh                build all binaries
                    common.py               configurations and helper functions
                    run_detection.py        Phase 2: detection matrix (RQ1, RQ2)
                    run_mte_experiments.py  Phase 4 tag space + RQ3 sync/async probe
                    run_perf.py             Phase 3: runtime and peak memory (RQ4)
                    run_perf_counters.py    Phase 3: perf stat counters (RQ4, x86-64)
                    make_figures.py         figures/ and results/tables.tex, numbers.tex
run_all.sh          runs every step above in order
results/            raw CSVs, summaries, logs, generated LaTeX tables
figures/            generated plots (PDF and PNG)
report/             report.tex -> report.pdf
slides/             slides.tex -> slides.pdf
sysroot-glibc2.36/  Debian 12 arm64 glibc 2.36 (runtime library for AArch64 binaries)
.vscode/tasks.json  one VS Code task per step
```
`build/` is created by step 4 and can be deleted at any time.

---

## 2. Requirements
Tested on **Ubuntu 26.04 LTS, x86-64** (AMD Ryzen 5 5600H) with:

| Tool | Version used | Used for |
|---|---|---|
| `gcc` | 15.2 | x86-64 builds, ASan |
| `aarch64-linux-gnu-gcc` and binutils | 15.2 / 2.46 | AArch64 builds; `addr2line`, `nm`, `objdump` for symbolising faults |
| `qemu-aarch64` (`qemu-user`) | 10.2.1 | running AArch64 binaries with MTE |
| Python 3 + matplotlib | 3.10.7 | experiment scripts and figures |
| `perf` (`linux-perf`) | kernel 7.0 | hardware counters |
| TeX Live + `latexmk` (beamer, booktabs, pifont, tikz) | 2025 | report and slides |

Any recent Ubuntu or Debian on x86-64 should work.

---

## 3. Steps from scratch (terminal)
All commands are run from the project folder unless stated otherwise.

### Step 1: Install the packages
```bash
sudo apt update
sudo apt install -y build-essential gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu \
    qemu-user python3 python3-matplotlib linux-perf curl \
    latexmk texlive-latex-recommended texlive-latex-extra texlive-fonts-recommended texlive-pictures
```
On older Ubuntu releases, `perf` is in `linux-tools-common` and `linux-tools-$(uname -r)` instead of `linux-perf`.

### Step 2: Allow `perf` for normal users
```bash
sudo sysctl kernel.perf_event_paranoid=1
```
This is needed only for `run_perf_counters.py`. It is lost on reboot, so run it again after restarting.

### Step 3: Get glibc 2.36 for the AArch64 runs
Ubuntu's AArch64 glibc (2.43) reports a false MTE fault inside every `free()` when heap tagging is on.
So the AArch64 programs run against Debian 12's glibc 2.36, which is also the version Noh et al. used.
Skip this step if `sysroot-glibc2.36/lib/ld-linux-aarch64.so.1` already exists.
```bash
mkdir -p sysroot-glibc2.36/_deb
curl -L -o sysroot-glibc2.36/_deb/libc6_2.36-9+deb12u14_arm64.deb \
    https://deb.debian.org/debian/pool/main/g/glibc/libc6_2.36-9+deb12u14_arm64.deb
sha256sum sysroot-glibc2.36/_deb/libc6_2.36-9+deb12u14_arm64.deb
# expected: 01f4330719fd4f65580e16ea5a0527f372fca750e8f588d26deaf09f2d3b1cf4
dpkg-deb -x sysroot-glibc2.36/_deb/libc6_2.36-9+deb12u14_arm64.deb sysroot-glibc2.36
```
If Debian has removed that exact version, use the newest `libc6_2.36-9+deb12u*_arm64.deb` from the same directory.

### Step 4: Build all binaries
```bash
chmod +x scripts/build.sh run_all.sh
scripts/build.sh
```
This produces 67 binaries under `build/<arch>/<config>/`. The suite is built at `-O0` and the benchmarks at `-O2`.

### Step 5: Check that the setup works
Each of these runs one suite program; the comment shows what to expect.
```bash
# x86-64 ASan: prints "ERROR: AddressSanitizer: heap-buffer-overflow"
ASAN_OPTIONS=detect_leaks=0 build/x86_64/asan/heap_overflow

# AArch64 baseline under QEMU, tagging off: the bug goes unnoticed and it prints "Done."
GLIBC_TUNABLES=glibc.mem.tagging=0 qemu-aarch64 -cpu max -L sysroot-glibc2.36 build/aarch64/baseline/heap_overflow

# AArch64 MTE-sync: prints "[FAULT] sig=SEGV code=9(SEGV_MTESERR) ..."
GLIBC_TUNABLES=glibc.mem.tagging=3 qemu-aarch64 -cpu max -L sysroot-glibc2.36 build/aarch64/baseline/heap_overflow
```

### Step 6: Run the experiments
Run them in this order. Each script writes its CSVs to `results/`. Times are approximate, on the machine above.

| # | Command | Phase / RQ | Output | Time |
|---|---|---|---|---|
| 6a | `python3 scripts/run_detection.py --reps 20 \| tee results/log_detection.txt` | Phase 2, RQ1, RQ2 | `detection_runs.csv`, `detection_summary.csv` | ~10 min |
| 6b | `python3 scripts/run_mte_experiments.py` | Phase 4, RQ3 | `mode_probe.csv`, `tag_space_*.csv` | ~3 min |
| 6c | `python3 scripts/run_perf.py --reps 5 \| tee results/log_perf.txt` | Phase 3, RQ4 | `perf_runs.csv`, `perf_summary.csv` | ~15 min |
| 6d | `python3 scripts/run_perf_counters.py --reps 5 \| tee results/log_perf_counters.txt` | Phase 3, RQ4 | `perf_counters.csv` | ~4 min |

### Step 7: Make the figures and tables
```bash
python3 scripts/make_figures.py
```
This writes `figures/*.pdf|png`, `results/tables.tex` and `results/numbers.tex`. The report and slides read the numbers from these files.

### Step 8: Build the report and the slides
```bash
cd report && latexmk -pdf report.tex && cd ..
cd slides && latexmk -pdf slides.tex && cd ..
```
The outputs are `report/report.pdf` and `slides/slides.pdf`.

### Shortcut
Steps 4, 6 and 7 together:
```bash
./run_all.sh
```
Then do step 8.

---

## 4. Running in VS Code
1. Install VS Code, then open the project: **File → Open Folder…** and choose this folder (or run `code .` in it).
2. Do steps 1–3 of section 3 once, in VS Code's terminal (**Terminal → New Terminal**). They need `sudo` and an internet connection.
3. Run the steps as VS Code tasks with **Terminal → Run Task…** (or `Ctrl+Shift+P` → *Tasks: Run Task*). The tasks are defined in `.vscode/tasks.json`:

   | Task | Same as |
   |---|---|
   | `0. Check setup` | lists any missing tool, the sysroot status and the perf setting |
   | `1. Build all binaries` | step 4 (also the default build task, `Ctrl+Shift+B`) |
   | `2. Phase 2: detection matrix` | step 6a |
   | `3. Phase 4 + RQ3: MTE experiments` | step 6b |
   | `4. Phase 3: runtime and memory` | step 6c |
   | `5. Phase 3: perf stat counters (x86-64)` | step 6d |
   | `6. Figures and tables` | step 7 |
   | `7. Build report and slides` | step 8 |
   | `Run everything (steps 1-7)` | all of the above, in order |

   Run `0. Check setup` first: every line should say `ok`.
4. Open `report/report.pdf`, `slides/slides.pdf` or any file in `figures/` from the Explorer to view the results.

Optional extensions: **C/C++** (Microsoft) for reading the C sources, **Python** (Microsoft) for the scripts, and **LaTeX Workshop** to edit the report with a live PDF preview.
None of them is needed to run the tasks.

---

## 5. On an MTE-capable ARM board
On an AArch64 Linux machine with MTE (for example a Pixel 8 or later running Linux, or an AmpereOne server), the same scripts run natively.
- `scripts/common.py` detects the host architecture and drops QEMU.
- `build.sh` then compiles with the native `gcc`, and ASan is added to the AArch64 configurations.
- Step 3 is not needed if the board's glibc does not fault inside `free()` with tagging on.
- The MTE timings are then real hardware overheads instead of emulation cost.

---

## 6. Notes on methodology
- The suite is compiled at `-O0`, because at `-O1` and above GCC deletes these undefined-behaviour accesses as dead code. As a result `_FORTIFY_SOURCE` is inactive for the suite. Benchmarks are compiled at `-O2`.
- `-std=gnu17` avoids C23 symbol versions (GLIBC_2.38), so the AArch64 binaries run against glibc 2.36.
- Every (program, configuration) pair is run 20 times, because MTE tags and allocator reuse are random.
- MTE runs in QEMU check functional behaviour only. QEMU checks tags in software, so its timings show emulation cost, not MTE hardware overhead. All AArch64 slowdowns are relative to the AArch64 baseline under QEMU.
- Runtime is the median wall-clock time of 5 runs after a warm-up, and memory is `ru_maxrss` from `wait4`.
- `perf stat` is used only for x86-64. Under QEMU it would count the emulator's own instructions.
