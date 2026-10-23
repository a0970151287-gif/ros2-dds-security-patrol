#!/usr/bin/env python3
"""ROSPaCe: how much of a published score is the split protocol?

## Why this exists

The committee question this answers is "the literature reports ~0.99, why does
this project report 0.4655?". The project's own numbers come from a sealed,
session-level holdout. ROSPaCe -- the closest public ROS 2 intrusion dataset --
ships two official usage notes, and they split the same data two ways:

* usage note A: every packet is a row, rows are shuffled, 60/40
  (``train_test_split(..., test_size=0.4, random_state=42)``);
* usage note B: a block is one ``observe`` stretch plus the attack stretch that
  follows it, and 60% of the blocks go to training.

Note B left its confusion matrix in the notebook (TN 2,085,218 / FP 434,632 /
FN 403,798 / TP 7,309,544), so its balanced accuracy is known: 0.887583. Note A
left none. This tool holds the model, the features and the sampled rows fixed
and changes only the split, so the difference is attributable to the split.

## What the protocol is

It is pre-registered in ``文件/預測_ROSPaCe的切分協定_2026-10-23.md``, committed
on its own before this file. The constants below are copied from it; if the two
ever disagree, the registration wins and the run is reported as a deviation.

## What it deliberately does not do

* **It never tunes anything.** The model is the authors' own XGBoost config.
* **It never relabels.** ``nmap SYN flood`` actually runs ``ipv6-ra-flood``
  (the authors' ``attack.py``), but this question is about their protocol on
  their labels, so the labels are taken as published.
* **It never touches this project's data or seals.** External data only.

Usage:

    python3 工具腳本/rospace_split_protocols.py \\
        --csv ~/rospace/complete_dataset.csv \\
        --feature-columns-from ~/rospace/reduced/ROSPaCe_reduced_1.csv \\
        --output 文件/ROSPaCe切分協定_<date>.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np

SCHEMA = "rospace-split-protocols/v1"
LABEL_COLUMN = "attack"
TIME_COLUMN = "timestamp"
NORMAL_LABEL = "observe"
KNOWN_LABELS = (
    "observe",
    "metasploit SYN flood",
    "nmap SYN flood",
    "nmap discovery",
    "ros2 reconnaissance",
    "ros2 node crashing",
    "ros2 reflection",
)
# The authors' own printout of the complete dataset
# (4_reduced_and_noperiodicity_dataset/reduced_dataset_composition.ipynb).
AUTHOR_LABEL_COUNTS = {
    "metasploit SYN flood": 14_696_890,
    "nmap SYN flood": 7_993_846,
    "observe": 6_645_324,
    "nmap discovery": 500_000,
    "ros2 reconnaissance": 401_494,
    "ros2 node crashing": 5_743,
    "ros2 reflection": 3_753,
}
AUTHOR_BLOCK_BA = 0.887583
REPRO_TOLERANCE = 0.05

SEEDS = (42, 43, 44, 45, 46)
SAMPLE_SEED = 20261023
TRAIN_FRACTION = 0.6
RUN_GAP_SEC = 600.0
ROWS_PER_BLOCK = 5_000
MAX_ROWS = 4_000_000
PROXY_RHO = 0.9
PROXY_MIN_ROWS = 1_000
XGB_PARAMS = {"n_estimators": 10, "max_depth": 20, "learning_rate": 1.0}

R1_SUPPORT, R1_REFUTE = 0.05, 0.01
R2_SUPPORT, R2_REFUTE = 0.50, 0.10
R3_SUPPORT, R3_REFUTE = 0.05, 0.01
SHUFFLE_CEILING = 0.55

_EXCLUDED_PREFIXES = ("Unnamed",)
_HEX = re.compile(r"0[xX][0-9a-fA-F]+")


# ─────────────────────────── reading ───────────────────────────


def read_header(path: Path) -> list[str]:
    import pandas as pd

    return list(pd.read_csv(path, nrows=0).columns)


def feature_columns(header: list[str], hint: list[str] | None = None) -> list[str]:
    """Every column that may be a feature: never the time, the label or an index.

    This is the one place a leak through the column list could enter, so it is
    an assertion, not a filter that quietly drops what it does not recognise.
    """
    pool = hint if hint is not None else header
    missing = [c for c in pool if c not in header]
    if missing:
        raise ValueError(f"feature columns not in the data: {missing[:5]}")
    cols = [
        c for c in pool
        if c not in (TIME_COLUMN, LABEL_COLUMN)
        and not c.startswith(_EXCLUDED_PREFIXES)
    ]
    for c in cols:
        assert c != TIME_COLUMN and c != LABEL_COLUMN and not c.startswith("Unnamed")
    if not cols:
        raise ValueError("no feature columns left")
    return cols


def _iter_chunks(paths, usecols, chunksize):
    import pandas as pd

    offset = 0
    for path in paths:
        for chunk in pd.read_csv(
            path, usecols=usecols, chunksize=chunksize, dtype=str, low_memory=False
        ):
            yield offset, chunk
            offset += len(chunk)


@dataclass
class Scan:
    n_rows: int
    ts_ns: np.ndarray          # int64, NaT rows hold the minimum int64
    code: np.ndarray           # int8 index into KNOWN_LABELS, -1 = dropped
    label_counts: dict[str, int]
    dropped_no_label: int
    dropped_no_time: int


def scan_labels_and_time(paths, chunksize: int = 200_000) -> Scan:
    """Pass 1: time and label for every row, nothing else.

    An unknown label stops the run. Guessing what an unlisted label means is
    exactly the kind of silent choice a pre-registration exists to prevent.
    """
    import pandas as pd

    lookup = {name: i for i, name in enumerate(KNOWN_LABELS)}
    ts_parts, code_parts = [], []
    counts = {name: 0 for name in KNOWN_LABELS}
    no_label = no_time = 0
    for _, chunk in _iter_chunks(paths, [TIME_COLUMN, LABEL_COLUMN], chunksize):
        labels = chunk[LABEL_COLUMN]
        unknown = sorted(set(labels.dropna()) - set(lookup))
        if unknown:
            raise ValueError(f"unknown labels (refusing to guess): {unknown}")
        code = labels.map(lookup).fillna(-1).astype(np.int8).to_numpy(copy=True)
        ts = pd.to_datetime(chunk[TIME_COLUMN], errors="coerce", format="ISO8601")
        bad_time = ts.isna().to_numpy()
        ts_ns = ts.to_numpy(dtype="datetime64[ns]").astype(np.int64)
        no_label += int((code < 0).sum())
        no_time += int((bad_time & (code >= 0)).sum())
        code[bad_time] = -1
        for name, n in labels[code >= 0].value_counts().items():
            counts[str(name)] += int(n)
        ts_parts.append(ts_ns)
        code_parts.append(code)
    ts_all = np.concatenate(ts_parts) if ts_parts else np.empty(0, np.int64)
    code_all = np.concatenate(code_parts) if code_parts else np.empty(0, np.int8)
    return Scan(len(ts_all), ts_all, code_all, counts, no_label, no_time)


# ─────────────────────────── structure ───────────────────────────


@dataclass
class Structure:
    order: np.ndarray          # valid global rows, in time order
    run: np.ndarray            # run id per row of `order`
    block: np.ndarray          # block id per row of `order`
    block_key: list[str]       # stratification key per block
    block_run: np.ndarray      # run id per block
    run_start_ns: np.ndarray   # start time per run
    gaps_sec: np.ndarray       # every positive gap between consecutive rows


def build_structure(ts_ns, code, run_gap_sec: float = RUN_GAP_SEC) -> Structure:
    """Runs, sequences and blocks, defined exactly as in the registration.

    * run: a new run starts where consecutive rows are more than
      ``run_gap_sec`` apart;
    * sequence: a maximal stretch of one label inside one run;
    * block: an ``observe`` sequence plus every attack sequence after it, up to
      the next ``observe`` sequence or the end of the run. Attack sequences at
      the start of a run, before any ``observe``, form a block of their own.
    """
    valid = np.flatnonzero(code >= 0)
    if valid.size == 0:
        raise ValueError("no labelled rows")
    order = valid[np.lexsort((valid, ts_ns[valid]))]
    t = ts_ns[order]
    c = code[order]
    gaps = np.diff(t)
    run_break = np.concatenate(([True], gaps > int(run_gap_sec * 1e9)))
    run = np.cumsum(run_break) - 1
    seq_start = run_break | np.concatenate(([True], c[1:] != c[:-1]))
    normal = KNOWN_LABELS.index(NORMAL_LABEL)
    block_start = seq_start & ((c == normal) | run_break)
    block = np.cumsum(block_start) - 1
    n_blocks = int(block[-1]) + 1
    keys: list[set[str]] = [set() for _ in range(n_blocks)]
    starts = np.flatnonzero(seq_start)
    for s in starts:
        if c[s] != normal:
            keys[block[s]].add(KNOWN_LABELS[c[s]])
    block_key = ["+".join(sorted(k)) if k else NORMAL_LABEL for k in keys]
    block_run = run[np.flatnonzero(block_start)]
    run_start_ns = t[np.flatnonzero(run_break)]
    return Structure(order, run, block, block_key, block_run, run_start_ns,
                     gaps[gaps > 0] / 1e9)


@dataclass
class Sample:
    rows: np.ndarray           # selected global rows, ascending
    block: np.ndarray          # block id per selected row (aligned with rows)
    run: np.ndarray
    rows_per_block: int
    deviation: str | None


def sample_rows(st: Structure, rows_per_block: int = ROWS_PER_BLOCK,
                max_rows: int = MAX_ROWS, seed: int = SAMPLE_SEED) -> Sample:
    """Up to ``rows_per_block`` uniform rows per block; small blocks keep all.

    If the total would exceed ``max_rows`` the per-block cap shrinks until it
    fits, and that is recorded as a deviation rather than applied silently.
    """
    sizes = np.bincount(st.block)
    cap, deviation = rows_per_block, None
    while np.minimum(sizes, cap).sum() > max_rows and cap > 1:
        cap = max(1, int(cap * max_rows / np.minimum(sizes, cap).sum()))
    if cap != rows_per_block:
        deviation = f"rows_per_block reduced {rows_per_block} -> {cap} to fit max_rows={max_rows}"
    rng = np.random.default_rng(seed)
    by_block = np.argsort(st.block, kind="stable")
    bounds = np.concatenate(([0], np.cumsum(sizes)))
    picked = []
    for b in range(len(sizes)):
        members = by_block[bounds[b]:bounds[b + 1]]
        if members.size > cap:
            members = rng.choice(members, cap, replace=False)
        picked.append(members)
    pos = np.sort(np.concatenate(picked))
    rows = st.order[pos]
    keep = np.argsort(rows, kind="stable")
    return Sample(rows[keep], st.block[pos][keep], st.run[pos][keep], cap, deviation)


def load_features(paths, cols: list[str], rows: np.ndarray,
                  chunksize: int = 200_000) -> tuple[np.ndarray, dict]:
    """Pass 2: only the sampled rows, encoded without ever looking at a label.

    Per value: a number stays a number, ``0x..`` becomes its integer, anything
    else is a string. Strings are coded per column by the rank of their 64-bit
    hash, as negative codes (-2, -3, ...), so they never collide with numbers;
    missing is -1, like the authors' ``fillna(-1)``.

    Memory: a chunk is read as Python strings, about 55 bytes per cell, so
    200,000 rows x 60 columns is ~0.7 GB; the matrix is float32 from the start
    (XGBoost trains on float32 anyway). At 4,000,000 sampled rows that keeps
    the peak near 2 GB, inside the 9 GB WSL limit (C2C-107).
    """
    import pandas as pd

    n_total = int(rows.max()) + 1 if rows.size else 0
    wanted = np.zeros(n_total, dtype=bool)
    wanted[rows] = True
    X = np.full((rows.size, len(cols)), np.nan, dtype=np.float32)
    str_pos: list[list[np.ndarray]] = [[] for _ in cols]
    str_hash: list[list[np.ndarray]] = [[] for _ in cols]
    filled = 0
    for offset, chunk in _iter_chunks(paths, cols, chunksize):
        if offset >= n_total:
            break
        m = wanted[offset:offset + len(chunk)]
        if m.size < len(chunk):
            m = np.concatenate((m, np.zeros(len(chunk) - m.size, bool)))
        if not m.any():
            continue
        part = chunk.loc[m, cols]
        dest = np.arange(filled, filled + len(part))
        for j, col in enumerate(cols):
            s = part[col]
            num = pd.to_numeric(s, errors="coerce").to_numpy(dtype=np.float64, copy=True)
            rest = s.notna().to_numpy() & np.isnan(num)
            if rest.any():
                vals = s[rest]
                is_hex = vals.str.fullmatch(_HEX).fillna(False).to_numpy()
                if is_hex.any():
                    idx = np.flatnonzero(rest)[is_hex]
                    num[idx] = [float(int(v, 16)) for v in vals[is_hex]]
                strs = vals[~is_hex]
                if len(strs):
                    str_pos[j].append(dest[np.flatnonzero(rest)[~is_hex]])
                    str_hash[j].append(
                        pd.util.hash_pandas_object(strs, index=False).to_numpy()
                    )
            X[dest, j] = num
        filled += len(part)
    if filled != rows.size:
        raise ValueError(f"pass 2 found {filled} of {rows.size} sampled rows")
    string_columns = []
    for j, col in enumerate(cols):
        if str_pos[j]:
            pos = np.concatenate(str_pos[j])
            h = np.concatenate(str_hash[j])
            _, inverse = np.unique(h, return_inverse=True)
            X[pos, j] = -(inverse.astype(np.float32) + 2.0)
            string_columns.append(col)
    X[~np.isfinite(X)] = -1.0
    return X, {"string_coded_columns": string_columns}


# ─────────────────────────── time proxies ───────────────────────────


def detect_time_proxies(X, ts_ns, run, cols, rho: float = PROXY_RHO,
                        min_rows: int = PROXY_MIN_ROWS) -> dict:
    """A feature is a time proxy if it is monotone in time inside the runs.

    Median |Spearman(feature, time)| across runs with at least ``min_rows``
    sampled rows. No label is read, so the list can be fixed before any split.
    """
    from scipy.stats import spearmanr

    per_col = {}
    runs = [r for r in np.unique(run) if (run == r).sum() >= min_rows]
    for j, col in enumerate(cols):
        rhos = []
        for r in runs:
            m = run == r
            x = X[m, j]
            if np.ptp(x) == 0:
                continue
            value = spearmanr(x, ts_ns[m]).statistic
            if np.isfinite(value):
                rhos.append(abs(float(value)))
        per_col[col] = float(np.median(rhos)) if rhos else 0.0
    proxies = sorted(c for c, v in per_col.items() if v >= rho)
    return {"runs_used": len(runs), "median_abs_rho": per_col, "proxies": proxies}


# ─────────────────────────── splits ───────────────────────────


def split_rows(n: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Usage note A: rows shuffled, 60/40 -- the authors' own call."""
    from sklearn.model_selection import train_test_split

    tr, te = train_test_split(np.arange(n), test_size=1 - TRAIN_FRACTION,
                              random_state=seed)
    return np.sort(tr), np.sort(te)


def split_blocks(block, block_key, seed: int) -> tuple[np.ndarray, np.ndarray, list]:
    """Usage note B, stratified: 60% of each kind of block goes to training.

    A kind with a single block goes to training only and is reported, because
    a class that exists on one side alone cannot be measured.
    """
    rng = np.random.default_rng(seed)
    present = np.unique(block)
    strata: dict[str, list[int]] = {}
    for b in present:
        strata.setdefault(block_key[b], []).append(int(b))
    train_blocks, singletons = set(), []
    for key in sorted(strata):
        members = np.array(sorted(strata[key]))
        rng.shuffle(members)
        if members.size == 1:
            singletons.append(key)
            train_blocks.add(int(members[0]))
            continue
        k = min(max(1, round(TRAIN_FRACTION * members.size)), members.size - 1)
        train_blocks.update(int(b) for b in members[:k])
    in_train = np.isin(block, list(train_blocks))
    tr, te = np.flatnonzero(in_train), np.flatnonzero(~in_train)
    assert not set(np.unique(block[tr])) & set(np.unique(block[te]))
    return tr, te, singletons


def split_chrono(run, run_start_ns) -> tuple[np.ndarray, np.ndarray] | None:
    """Earliest runs train, later runs test; no fallback when runs are too few.

    This is the analogue of this project's own finding (C2C-116): a later batch
    has a background the model never saw.
    """
    present = np.unique(run)
    if present.size < 3:
        return None
    ordered = present[np.argsort(run_start_ns[present], kind="stable")]
    counts = np.array([(run == r).sum() for r in ordered])
    share = np.cumsum(counts) / counts.sum()
    k = int(np.searchsorted(share, TRAIN_FRACTION) + 1)
    k = min(max(k, 1), ordered.size - 1)
    in_train = np.isin(run, ordered[:k])
    tr, te = np.flatnonzero(in_train), np.flatnonzero(~in_train)
    assert not set(np.unique(run[tr])) & set(np.unique(run[te]))
    return tr, te


# ─────────────────────────── model ───────────────────────────


def _model(n_classes: int, seed: int):
    from xgboost import XGBClassifier

    objective = "binary:logistic" if n_classes == 2 else "multi:softprob"
    return XGBClassifier(objective=objective, random_state=seed, n_jobs=-1,
                         tree_method="hist", **XGB_PARAMS)


def evaluate(X, y_code, tr, te, seed: int, *, multiclass: bool,
             shuffle_labels: bool = False) -> dict | None:
    """Fit on ``tr``, score on ``te``. Returns None when a class is missing."""
    from sklearn.metrics import average_precision_score, balanced_accuracy_score

    normal = KNOWN_LABELS.index(NORMAL_LABEL)
    if multiclass:
        y = y_code.astype(np.int64)
    else:
        y = (y_code != normal).astype(np.int64)
    y_tr = y[tr].copy()
    if shuffle_labels:
        np.random.default_rng(seed).shuffle(y_tr)
    classes = np.unique(y_tr)
    if classes.size < 2:
        return None
    te_mask = np.isin(y[te], classes)
    te = te[te_mask]
    if te.size == 0 or np.unique(y[te]).size < 2:
        return None
    model = _model(classes.size, seed)
    model.fit(X[tr], np.searchsorted(classes, y_tr))
    pred = classes[model.predict(X[te]).astype(np.int64)]
    out = {
        "balanced_accuracy": float(balanced_accuracy_score(y[te], pred)),
        "n_train": int(tr.size), "n_test": int(te.size),
        "test_rows_dropped_unseen_class": int((~te_mask).sum()),
        "n_classes": int(classes.size),
    }
    if not multiclass:
        p_attack = model.predict_proba(X[te])[:, 1]
        out["pr_auc_attack"] = float(average_precision_score(y[te] == 1, p_attack))
        out["pr_auc_normal"] = float(average_precision_score(y[te] == 0, 1 - p_attack))
    return out


def _summary(results: list[dict]) -> dict:
    ba = [r["balanced_accuracy"] for r in results]
    return {"per_seed": results, "mean_ba": float(np.mean(ba)),
            "min_ba": float(np.min(ba)), "max_ba": float(np.max(ba))}


# 0.95 - 0.90 is 0.04999999999999993 in floating point. A boundary the
# registration calls "supported" must not turn into "undecided" because of the
# last bit (C2C-123 recorded the same trap: exact comparison of values that are
# mathematically equal).
_EPS = 1e-9


def _verdict(value, support, refute) -> str:
    if value is None:
        return "not_evaluable"
    if value >= support - _EPS:
        return "supported"
    return "refuted" if value < refute - _EPS else "undecided"


def judge(res: dict) -> dict:
    """The registration's rules, applied mechanically to the numbers."""
    def mean(proto, fset, task="binary"):
        node = res["protocols"].get(proto, {}).get(fset, {}).get(task)
        return node["mean_ba"] if node else None

    v = {}
    row, blk = mean("row", "all"), mean("block", "all")
    gap = None if row is None or blk is None else row - blk
    v["R1_gap_row_minus_block"] = gap
    v["R1"] = _verdict(gap, R1_SUPPORT, R1_REFUTE)

    row_np, blk_np = mean("row", "no_time_proxy"), mean("block", "no_time_proxy")
    if gap is None or gap <= R1_REFUTE or row_np is None or blk_np is None:
        v["R2_shrink"], v["R2"] = None, "not_evaluable"
    else:
        shrink = 1 - (row_np - blk_np) / gap
        v["R2_shrink"] = shrink
        v["R2"] = _verdict(shrink, R2_SUPPORT, R2_REFUTE)

    chrono = mean("chrono", "all")
    drop = None if chrono is None or blk is None else blk - chrono
    v["R3_block_minus_chrono"] = drop
    v["R3"] = _verdict(drop, R3_SUPPORT, R3_REFUTE)

    row_m, blk_m = mean("row", "all", "multiclass"), mean("block", "all", "multiclass")
    if None in (row, blk, row_m, blk_m):
        v["R4"] = "not_evaluable"
    elif max(row - blk, row_m - blk_m) <= R1_REFUTE + _EPS:
        # Nothing was inflated on either task, so "identification is inflated
        # more than detection" would be true of two noise values. The synthetic
        # negative control printed "supported" here before this branch existed
        # -- the same vacuous truth C2C-127 found in its G4.
        v["R4"] = "not_evaluable"
    else:
        k = res["protocols"]["block"]["all"]["multiclass"]["per_seed"][0]["n_classes"]
        chance = 1.0 / k
        norm_bin = (row - blk) / 0.5
        norm_mc = (row_m - blk_m) / (1 - chance)
        v["R4_normalised_gaps"] = {"binary": norm_bin, "multiclass": norm_mc}
        v["R4"] = "supported" if norm_mc >= norm_bin else "refuted"

    c1 = blk
    v["C1_block_ba"] = c1
    v["C1"] = ("not_evaluable" if c1 is None else
               "pass" if abs(c1 - AUTHOR_BLOCK_BA) <= REPRO_TOLERANCE else "fail")
    shuffled = res.get("controls", {}).get("label_shuffle", {})
    v["C2"] = ("pass" if shuffled and all(
        s is None or s["balanced_accuracy"] <= SHUFFLE_CEILING for s in shuffled.values())
        else "not_evaluable" if not shuffled else "fail")
    return v


# ─────────────────────────── run ───────────────────────────


def sha256_files(paths) -> dict[str, str]:
    out = {}
    for p in paths:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for block in iter(lambda: f.read(1 << 24), b""):
                h.update(block)
        out[str(p)] = h.hexdigest()
    return out


def run(paths, hint_cols, *, rows_per_block=ROWS_PER_BLOCK, max_rows=MAX_ROWS,
        seeds=SEEDS, chunksize=200_000, hash_inputs=True) -> dict:
    started = time.time()
    header = read_header(paths[0])
    for p in paths[1:]:
        if read_header(p) != header:
            raise ValueError(f"{p} has a different header from {paths[0]}")
    for need in (TIME_COLUMN, LABEL_COLUMN):
        if need not in header:
            raise ValueError(
                f"column {need!r} missing: blocks need time and label "
                "(registration §四: no fallback to file order)")
    cols = feature_columns(header, hint_cols)

    scan = scan_labels_and_time(paths, chunksize)
    st = build_structure(scan.ts_ns, scan.code)
    sm = sample_rows(st, rows_per_block, max_rows)
    X, enc = load_features(paths, cols, sm.rows, chunksize)
    y = scan.code[sm.rows]
    ts = scan.ts_ns[sm.rows]
    proxies = detect_time_proxies(X, ts, sm.run, cols)
    keep = np.array([c not in proxies["proxies"] for c in cols])

    fsets = {"all": X}
    if not keep.all() and keep.any():
        fsets["no_time_proxy"] = X[:, keep]

    res = {
        "schema": SCHEMA,
        "registration": "文件/預測_ROSPaCe的切分協定_2026-10-23.md",
        "holdout_reads": 0,
        "inputs": {"paths": [str(p) for p in paths],
                   "sha256": sha256_files(paths) if hash_inputs else None},
        "constants": {
            "seeds": list(seeds), "sample_seed": SAMPLE_SEED,
            "train_fraction": TRAIN_FRACTION, "run_gap_sec": RUN_GAP_SEC,
            "rows_per_block_requested": rows_per_block,
            "rows_per_block_used": sm.rows_per_block, "max_rows": max_rows,
            "proxy_rho": PROXY_RHO, "proxy_min_rows": PROXY_MIN_ROWS,
            "xgb": XGB_PARAMS,
        },
        "deviations": [d for d in [sm.deviation] if d],
        "data": {
            "n_rows": scan.n_rows, "label_counts": scan.label_counts,
            "dropped_no_label": scan.dropped_no_label,
            "dropped_no_time": scan.dropped_no_time,
            "C0_matches_author_counts": scan.label_counts == AUTHOR_LABEL_COUNTS,
            "n_runs": int(st.run_start_ns.size),
            "n_blocks": len(st.block_key),
            "block_kinds": {k: st.block_key.count(k) for k in sorted(set(st.block_key))},
            "gap_sec_quantiles": (np.quantile(st.gaps_sec, [.5, .9, .99, .999, 1]).tolist()
                                  if st.gaps_sec.size else []),
            "n_sampled": int(sm.rows.size),
            "feature_columns": cols, **enc,
        },
        "time_proxies": proxies,
        "protocols": {},
        "controls": {},
    }

    splits = {"row": [], "block": [], "chrono": []}
    for s in seeds:
        splits["row"].append((s,) + split_rows(sm.rows.size, s))
        tr, te, singles = split_blocks(sm.block, st.block_key, s)
        splits["block"].append((s, tr, te))
        res["data"].setdefault("block_kinds_train_only", singles)
    chrono = split_chrono(sm.run, st.run_start_ns)
    if chrono is not None:
        splits["chrono"].append((seeds[0],) + chrono)

    for proto, items in splits.items():
        if not items:
            continue
        res["protocols"][proto] = {}
        for fname, Xf in fsets.items():
            node = {}
            for task in ("binary", "multiclass"):
                if proto == "chrono" and task == "multiclass":
                    continue
                outs = [evaluate(Xf, y, tr, te, s, multiclass=task == "multiclass")
                        for s, tr, te in items]
                outs = [o for o in outs if o is not None]
                if outs:
                    node[task] = _summary(outs)
            res["protocols"][proto][fname] = node

    res["controls"]["label_shuffle"] = {
        proto: evaluate(X, y, items[0][1], items[0][2], items[0][0],
                        multiclass=False, shuffle_labels=True)
        for proto, items in splits.items() if items
    }
    res["verdicts"] = judge(res)
    res["elapsed_sec"] = round(time.time() - started, 1)
    return res


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv", type=Path, nargs="+", required=True)
    parser.add_argument("--feature-columns-from", type=Path,
                        help="restrict features to this CSV's columns (the published reduced set)")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--chunksize", type=int, default=200_000)
    args = parser.parse_args(argv)
    if args.output.exists():
        print(f"⛔ {args.output} 已存在，拒絕覆寫（一次性的量測結果不可被蓋掉）")
        return 2
    hint = read_header(args.feature_columns_from) if args.feature_columns_from else None
    try:
        res = run(args.csv, hint, chunksize=args.chunksize)
    except ValueError as exc:
        print(f"⛔ {exc}")
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(res, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    v = res["verdicts"]
    print(f"R1 {v['R1']}  R2 {v['R2']}  R3 {v['R3']}  R4 {v['R4']}  "
          f"C1 {v['C1']}  C2 {v['C2']}  → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
