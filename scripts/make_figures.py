#!/usr/bin/env python3
"""Generate all figures (figures/*.pdf, *.png) and LaTeX tables
(results/tables.tex) from the CSV files in results/."""
import csv
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from common import FIGURES, RESULTS  # noqa: E402

# Reference palette (dataviz skill): categorical slots in fixed order, status
# colours reserved for detected / missed / crash.
SLOT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
GOOD, SERIOUS, CRITICAL = "#0ca30c", "#ec835a", "#d03b3b"
INK, INK2, GRID, SURF = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
CFG_COLOR = {"hardening": SLOT[0], "asan": SLOT[1], "mte-sync": SLOT[2], "mte-async": SLOT[3]}
CFG_LABEL = {"baseline": "Baseline", "hardening": "Hardening", "asan": "ASan",
             "mte-sync": "MTE-sync", "mte-async": "MTE-async"}

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": INK2, "axes.labelcolor": INK,
    "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "figure.facecolor": "white", "axes.facecolor": "white", "legend.frameon": False,
})


def read(name):
    with open(RESULTS / name) as fh:
        return list(csv.DictReader(fh))


def save(fig, name):
    FIGURES.mkdir(exist_ok=True)
    fig.savefig(FIGURES / f"{name}.pdf", bbox_inches="tight")
    fig.savefig(FIGURES / f"{name}.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


# --------------------------------------------------------------------------- #
SUITE = ["stack_overflow", "heap_overflow", "oob_read", "oob_write", "use_after_free", "double_free"]
BOUNDARY = ["intra_granule_overflow", "far_oob_into_live_object", "uaf_after_reallocation", "intra_object_overflow"]
PRETTY = {"stack_overflow": "Stack buffer overflow", "heap_overflow": "Heap buffer overflow",
          "oob_read": "Out-of-bounds read", "oob_write": "Out-of-bounds write",
          "use_after_free": "Use-after-free", "double_free": "Double-free",
          "intra_granule_overflow": "B1 Intra-granule overflow",
          "far_oob_into_live_object": "B2 Far OOB into live object",
          "uaf_after_reallocation": "B3 UAF after reallocation",
          "intra_object_overflow": "B4 Intra-object overflow"}
COLUMNS = [("x86_64", "baseline"), ("aarch64", "baseline"), ("x86_64", "hardening"),
           ("aarch64", "hardening"), ("x86_64", "asan"), ("aarch64", "mte-sync"), ("aarch64", "mte-async")]
COL_LABEL = ["Baseline\nx86-64", "Baseline\nAArch64", "Hardening\nx86-64", "Hardening\nAArch64",
             "ASan\nx86-64", "MTE-sync\nAArch64", "MTE-async\nAArch64"]


def short_mech(m):
    m = m.split(" x")[0]
    for key, s in [("stack canary", "canary"), ("FORTIFY", "fortify"), ("glibc allocator", "glibc check"),
                   ("ASan", "ASan"), ("MTE sync", "tag fault"), ("MTE async", "async fault"),
                   ("bounds-check", "bounds trap"), ("segfault", "crash"), ("hijack", "hijacked"),
                   ("silent", "silent")]:
        if key in m:
            return s
    return m


def detection():
    rows = {(r["platform"], r["program"], r["config"]): r for r in read("detection_summary.csv")}
    progs = SUITE + BOUNDARY

    # -- figure: detection matrix --------------------------------------------
    fig, ax = plt.subplots(figsize=(9.2, 5.0))
    ax.grid(False)
    for i, prog in enumerate(progs):
        for j, col in enumerate(COLUMNS):
            r = rows.get((col[0], prog, col[1]))
            if not r:
                continue
            rate = float(r["detection_rate"])
            mech = short_mech(r["mechanisms"])
            if rate >= 0.5:
                color, status = GOOD, "detected"
            elif mech == "crash":
                color, status = SERIOUS, "crash"
            else:
                color, status = CRITICAL, "missed"
            ax.add_patch(plt.Rectangle((j + 0.04, i + 0.06), 0.92, 0.88, color=color,
                                       alpha=0.18 if status != "detected" else 0.28, lw=0))
            sym = {"detected": "✓", "crash": "!", "missed": "✗"}[status]
            n = int(r["runs"])
            txt = f"{sym} {mech}\n{int(r['detected'])}/{n}"
            ax.text(j + 0.5, i + 0.5, txt, ha="center", va="center", fontsize=7.2, color=INK)
    ax.set_xlim(0, len(COLUMNS))
    ax.set_ylim(len(progs), 0)
    ax.set_xticks([j + 0.5 for j in range(len(COLUMNS))], COL_LABEL, fontsize=7.8)
    ax.xaxis.tick_top()
    ax.set_yticks([i + 0.5 for i in range(len(progs))], [PRETTY[p] for p in progs], fontsize=8)
    ax.axhline(len(SUITE), color=INK2, lw=1)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    ax.text(len(COLUMNS), len(progs) + 0.55,
            "✓ detected   ! crashed without a report   ✗ missed (program kept running)   n/N = runs detected",
            ha="right", va="top", fontsize=7.2, color=INK2)
    save(fig, "detection_matrix")

    # -- LaTeX table: proposal Table 1 ----------------------------------------
    def cell(plat, prog, cfg):
        r = rows.get((plat, prog, cfg))
        if not r:
            return "--"
        rate = float(r["detection_rate"])
        mech = short_mech(r["mechanisms"])
        mark = r"\cmark" if rate >= 0.5 else (r"\crash" if mech == "crash" else r"\xmark")
        frac = "" if rate in (0.0, 1.0) else f" ({int(r['detected'])}/{r['runs']})"
        return f"{mark} {mech}{frac}"

    analysis = {
        "stack_overflow": "Only stack defenses (canary, ASan) see it; glibc MTE tags heap only",
        "heap_overflow": "Spatial: crosses a 16-B granule $\\Rightarrow$ MTE detects",
        "oob_read": "Spatial: lands in granule padding $\\Rightarrow$ MTE misses",
        "oob_write": "Spatial: lands in granule padding $\\Rightarrow$ MTE misses",
        "use_after_free": "Temporal: freed memory retagged $\\Rightarrow$ MTE detects",
        "double_free": "Allocator interaction: glibc tcache check and MTE both catch",
        "intra_granule_overflow": "Byte-precise ASan vs 16-B MTE granularity",
        "far_oob_into_live_object": "Jumps ASan redzone; MTE tag mismatch",
        "uaf_after_reallocation": "ASan quarantine evicted; MTE probabilistic",
        "intra_object_overflow": "Inside one object: only index bounds check; CFI territory",
    }
    lines = [r"\begin{tabular}{@{}lllllll p{4.2cm}@{}}", r"\toprule",
             r"Vulnerability & \multicolumn{2}{c}{Baseline} & \multicolumn{2}{c}{Hardening} & ASan & MTE-sync / MTE-async & Analysis \\",
             r" & x86 & A64 & x86 & A64 & x86 & A64 & \\", r"\midrule"]
    for prog in progs:
        if prog == BOUNDARY[0]:
            lines.append(r"\midrule")
        c = [cell("x86_64", prog, "baseline"), cell("aarch64", prog, "baseline"),
             cell("x86_64", prog, "hardening"), cell("aarch64", prog, "hardening"),
             cell("x86_64", prog, "asan"),
             cell("aarch64", prog, "mte-sync") + " / " + short_mech(rows[("aarch64", prog, "mte-async")]["mechanisms"])
             if ("aarch64", prog, "mte-async") in rows else "--"]
        lines.append(f"{PRETTY[prog]} & " + " & ".join(c) + f" & {analysis[prog]} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
WL = ["alloc-small", "alloc-medium", "alloc-large", "access-seq", "access-rand", "kv-store"]


def perf():
    rows = read("perf_summary.csv")
    d = {(r["platform"], r["workload"], r["config"]): r for r in rows}
    out = []
    for plat, cfgs, name, title, log in [
        ("x86_64", ["hardening", "asan"], "perf_x86", "Runtime overhead on x86-64 (native hardware)", False),
        ("aarch64", ["hardening", "mte-sync", "mte-async"], "perf_qemu",
         "Runtime under QEMU emulation (emulation cost, not MTE hardware cost)", True),
    ]:
        for metric, ylabel, suffix in [("slowdown_vs_baseline", "slowdown vs. baseline (×)", ""),
                                       ("rss_vs_baseline", "peak RSS vs. baseline (×)", "_rss")]:
            fig, ax = plt.subplots(figsize=(7.2, 2.9))
            w = 0.8 / len(cfgs)
            for k, cfg in enumerate(cfgs):
                xs = [i + (k - (len(cfgs) - 1) / 2) * w for i in range(len(WL))]
                ys = [float(d[(plat, wl, cfg)][metric]) for wl in WL]
                ax.bar(xs, ys, width=w - 0.03, color=CFG_COLOR[cfg], label=CFG_LABEL[cfg], zorder=2)
                for x, y in zip(xs, ys):
                    ax.text(x, y * (1.04 if log else 1) + (0 if log else 0.03), f"{y:.2f}" if y < 10 else (f"{y:.1f}" if y < 100 else f"{y:.0f}"),
                            ha="center", va="bottom", fontsize=6.5, color=INK2)
            ax.axhline(1, color=INK2, lw=0.8, ls="--", zorder=3)
            ax.set_xticks(range(len(WL)), WL)
            if log and metric == "slowdown_vs_baseline":
                ax.set_yscale("log")
            ax.set_ylabel(ylabel)
            ax.set_title(title if not suffix else title.replace("Runtime", "Peak memory"), fontsize=9,
                         loc="left", color=INK)
            ax.legend(ncol=len(cfgs), loc="upper left", fontsize=8)
            ax.set_ylim(top=ax.get_ylim()[1] * (1.6 if log and not suffix else 1.15))
            save(fig, name + suffix)

    # table
    lines = [r"\begin{tabular}{@{}l" + "r" * 9 + r"@{}}", r"\toprule",
             r" & \multicolumn{3}{c}{x86-64 native: slowdown / RSS} & \multicolumn{6}{c}{AArch64 under QEMU: slowdown (RSS)} \\",
             r"\cmidrule(lr){2-4}\cmidrule(l){5-10}",
             r"Workload & base (s) & Hard. & ASan & base (s) & Hard. & MTE-sync & & MTE-async & \\", r"\midrule"]
    for wl in WL:
        x = [d[("x86_64", wl, c)] for c in ("baseline", "hardening", "asan")]
        a = [d[("aarch64", wl, c)] for c in ("baseline", "hardening", "mte-sync", "mte-async")]
        lines.append(
            f"{wl} & {float(x[0]['median_wall_s']):.2f} & {float(x[1]['slowdown_vs_baseline']):.2f}$\\times$ & "
            f"{float(x[2]['slowdown_vs_baseline']):.2f}$\\times$ / {float(x[2]['rss_vs_baseline']):.2f}$\\times$ & "
            f"{float(a[0]['median_wall_s']):.2f} & {float(a[1]['slowdown_vs_baseline']):.2f}$\\times$ & "
            f"{float(a[2]['slowdown_vs_baseline']):.1f}$\\times$ & ({float(a[2]['rss_vs_baseline']):.2f}) & "
            f"{float(a[3]['slowdown_vs_baseline']):.1f}$\\times$ & ({float(a[3]['rss_vs_baseline']):.2f}) \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    out.append("\n".join(lines))
    return out[0]


# --------------------------------------------------------------------------- #
def tag_space():
    dist = read("tag_space_distance.csv")
    xs = [int(r["distance_past_end"]) for r in dist]
    ys = [100 * float(r["rate"]) for r in dist]
    fig, ax = plt.subplots(figsize=(7.2, 2.7))
    ax.axhline(100 * 14 / 15, color=INK2, lw=0.8, ls="--")
    ax.text(1030, 100 * 14 / 15 + 0.4, "ideal 14/15 = 93.3%", ha="right", va="bottom", fontsize=7, color=INK2)
    ax.plot(xs, ys, color=SLOT[0], lw=2, marker="o", ms=3.2, zorder=3)
    hdr = [(x, y) for x, y in zip(xs, ys) if x % 64 == 0]
    ax.scatter(*zip(*hdr), s=26, color=SLOT[1], zorder=4, label="lands on a chunk header (tag 0)")
    ax.annotate("adjacent object:\nconsecutive IRG tags", xy=(32, ys[2]), xytext=(110, 85.6),
                fontsize=7, color=INK2, arrowprops=dict(arrowstyle="-", color=INK2, lw=0.6))
    ax.set_xlabel("distance past end of a 48-byte object (bytes)")
    ax.set_ylabel("detection rate (%)")
    ax.set_ylim(84, 101.5)
    ax.legend(loc="lower right", fontsize=7.5)
    ax.set_title("MTE-sync detection of a linear OOB load vs. distance (2000 trials per point)",
                 fontsize=9, loc="left")
    save(fig, "tag_distance")

    g = read("tag_space_granule.csv")
    n = [int(r["request"]) for r in g]
    ff = [int(r["first_fault_mode"]) for r in g]
    fig, ax = plt.subplots(figsize=(4.6, 2.9))
    ax.fill_between(n, n, ff, step="post", color=SLOT[2], alpha=0.25, lw=0, label="undetected slack (MTE)")
    ax.step(n, ff, where="post", color=SLOT[2], lw=2, label="first faulting offset, MTE")
    ax.plot(n, n, color=SLOT[1], lw=2, label="first faulting offset, ASan (= size)")
    ax.set_xlabel("requested allocation size (bytes)")
    ax.set_ylabel("offset of first detected byte")
    ax.legend(fontsize=7, loc="upper left")
    ax.set_title("Detection granularity", fontsize=9, loc="left")
    save(fig, "granule")

    reuse = read("tag_space_reuse.csv")[0]
    irg = read("tag_space_irg.csv")[0]
    trials = int(reuse["same_address_realloc"])
    coll = int(reuse["undetected_after_realloc"]) / trials
    fig, ax = plt.subplots(figsize=(4.6, 2.6))
    labels = ["ideal\n(uniform, 15 tags)", "IRG lag-1\nrepeat (QEMU)", "stale ptr undetected\nafter realloc"]
    vals = [100 / 15, 100 * float(irg["p_equal_lag1"]), 100 * coll]
    bars = ax.bar(range(3), vals, color=[INK2, SLOT[3], SLOT[0]], width=0.6, zorder=2)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.2, f"{v:.1f}%", ha="center", fontsize=8)
    ax.set_xticks(range(3), labels, fontsize=7.5)
    ax.set_ylabel("probability (%)")
    ax.set_ylim(0, max(vals) * 1.25)
    ax.set_title("Accidental tag match after reuse", fontsize=9, loc="left")
    save(fig, "tag_reuse")

    h = read("tag_space_tag_histogram.csv")
    return dict(reuse=reuse, irg=irg, coll=coll,
                hist0=int(h[0]["count"]), histmin=min(int(r["count"]) for r in h[1:]),
                histmax=max(int(r["count"]) for r in h[1:]))


def counters():
    """Table of `perf stat` counters for x86-64 (ASan and hardening relative to baseline)."""
    d = {(r["workload"], r["config"]): {k: float(v) for k, v in r.items() if k not in ("workload", "config")}
         for r in read("perf_counters.csv")}
    lines = [r"\begin{tabular}{@{}lrrrrrr@{}}", r"\toprule",
             r" & Hard. & \multicolumn{5}{c}{ASan relative to baseline} \\", r"\cmidrule(l){3-7}",
             r"Workload & instr. & instr. & cycles & IPC (base$\to$ASan) & cache-miss & page-faults \\",
             r"\midrule"]
    x = r"$\times$"
    for wl in WL:
        b, h, a = d[(wl, "baseline")], d[(wl, "hardening")], d[(wl, "asan")]
        lines.append(f"{wl} & {h['instructions'] / b['instructions']:.2f}{x} & "
                     f"{a['instructions'] / b['instructions']:.1f}{x} & {a['cycles'] / b['cycles']:.1f}{x} & "
                     f"{b['ipc']:.2f}$\\to${a['ipc']:.2f} & {a['cache-misses'] / b['cache-misses']:,.0f}{x} & "
                     f"{a['page-faults'] / b['page-faults']:,.0f}{x} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines).replace(",", "{,}")


def numbers(info):
    """Macros for numbers quoted in the report text (results/numbers.tex)."""
    import math
    perf_rows = {(r["platform"], r["workload"], r["config"]): r for r in read("perf_summary.csv")}
    asan = [float(perf_rows[("x86_64", w, "asan")]["slowdown_vs_baseline"]) for w in WL]
    asan_rss = [float(perf_rows[("x86_64", w, "asan")]["rss_vs_baseline"]) for w in WL]
    ratio = [float(perf_rows[("aarch64", w, "mte-async")]["median_wall_s"]) /
             float(perf_rows[("aarch64", w, "mte-sync")]["median_wall_s"]) for w in WL]
    gm = math.exp(sum(map(math.log, ratio)) / len(ratio))
    dist = read("tag_space_distance.csv")
    adj = [float(r["rate"]) for r in dist if 0 < int(r["distance_past_end"]) < 64]
    far = [float(r["rate"]) for r in dist if int(r["distance_past_end"]) >= 64 and int(r["distance_past_end"]) % 64]
    hist = read("tag_space_tag_histogram.csv")
    m = {
        "ReuseUndet": f"{100 * info['coll']:.1f}",
        "ReuseTrials": f"{int(info['reuse']['same_address_realloc']):,}".replace(",", "{,}"),
        "IrgLagOne": f"{100 * float(info['irg']['p_equal_lag1']):.1f}",
        "IrgLagTwo": f"{100 * float(info['irg']['p_equal_lag2']):.1f}",
        "HistN": f"{sum(int(r['count']) for r in hist):,}".replace(",", "{,}"),
        "HistMin": str(info["histmin"]), "HistMax": str(info["histmax"]),
        "FarMean": f"{100 * sum(far) / len(far):.1f}",
        "AdjMin": f"{100 * min(adj):.1f}", "AdjMax": f"{100 * max(adj):.1f}",
        "AsanMin": f"{min(asan):.2f}", "AsanMax": f"{max(asan):.1f}",
        "AsanRssMin": f"{min(asan_rss):.2f}", "AsanRssMax": f"{max(asan_rss):.1f}",
        "AsyncVsSync": f"{gm:.2f}",
    }
    c = {(r["workload"], r["config"]): r for r in read("perf_counters.csv")}
    rel = lambda wl, cfg, ev: float(c[(wl, cfg)][ev]) / float(c[(wl, "baseline")][ev])
    hard = [rel(w, "hardening", "instructions") for w in WL]
    m.update({
        "HardInstrMin": f"{min(hard):.2f}", "HardInstrMax": f"{max(hard):.2f}",
        "AsanSmallInstr": f"{rel('alloc-small', 'asan', 'instructions'):.0f}",
        "AsanSmallPf": f"{rel('alloc-small', 'asan', 'page-faults'):,.0f}".replace(",", "{,}"),
        "AsanLargePf": f"{rel('alloc-large', 'asan', 'page-faults'):.1f}",
        "AsanLargeMiss": f"{rel('alloc-large', 'asan', 'cache-misses'):.0f}",
        "AsanLargeIpc": f"{float(c[('alloc-large', 'asan')]['ipc']):.2f}",
        "BaseLargeIpc": f"{float(c[('alloc-large', 'baseline')]['ipc']):.2f}",
        "AsanSeqInstr": f"{rel('access-seq', 'asan', 'instructions'):.2f}",
        "AsanSeqCyc": f"{rel('access-seq', 'asan', 'cycles'):.2f}",
        "AsanRandInstr": f"{rel('access-rand', 'asan', 'instructions'):.2f}",
        "AsanRandCyc": f"{rel('access-rand', 'asan', 'cycles'):.2f}",
        "BaseRandIpc": f"{float(c[('access-rand', 'baseline')]['ipc']):.2f}",
        "AsanKvInstr": f"{rel('kv-store', 'asan', 'instructions'):.1f}",
        "AsanKvPf": f"{rel('kv-store', 'asan', 'page-faults'):.0f}",
    })
    (RESULTS / "numbers.tex").write_text("% generated by scripts/make_figures.py\n" + "".join(
        f"\\newcommand{{\\{k}}}{{{v}}}\n" for k, v in m.items()))
    return m


def main():
    t1 = detection()
    t2 = perf()
    t3 = counters()
    info = tag_space()
    print(numbers(info))
    (RESULTS / "tables.tex").write_text("% generated by scripts/make_figures.py\n"
                                       "\\newcommand{\\DetectionTable}{%\n" + t1 + "}\n"
                                       "\\newcommand{\\PerfTable}{%\n" + t2 + "}\n"
                                       "\\newcommand{\\CounterTable}{%\n" + t3 + "}\n")
    print("figures written to", FIGURES, "| tag-space:", info)


if __name__ == "__main__":
    main()
