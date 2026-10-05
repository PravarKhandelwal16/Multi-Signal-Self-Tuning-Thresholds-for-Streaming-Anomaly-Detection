# -*- coding: utf-8 -*-
"""
Step 2: Clean the CSE-CIC-IDS2018 Dataset
==========================================
Based on actual Step 1 inspection findings.

Cleaning operations (in order):
  1. Fix Web Attack label Unicode artifact (replace \\ufffd with en-dash)
  2. Replace +Inf in Flow Bytes/s and Flow Packets/s with NaN
  3. Remove rows where Flow Duration == 0 (root cause of NaN/Inf; these are malformed flows)
     -- This handles ALL NaN and Inf values in one step, without imputation
  4. Remove exact duplicate rows (keep=first to preserve row order)
  5. Verify no remaining NaN, Inf, or duplicates
  6. Save to processed/ directory without touching raw data

What is NOT done:
  - No imputation (NaN/Inf rows are removed because their root cause is a broken measurement)
  - No feature removal (Fwd Header Length.1 kept; that is Step 3/feature selection)
  - No normalization/scaling
  - No train/test split
  - No shuffling (row order preserved within each file)
  - Init_Win_bytes_backward = -1 is left as-is (valid sentinel)
"""

import sys
import io
import json
from pathlib import Path
from datetime import datetime
import numpy as np
import pandas as pd

# Force UTF-8 output streams for Windows consoles
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── Paths ──────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "MachineLearningCVE"
OUT_DIR = PROJECT_ROOT / "processed"
JSON_REPORT_PATH = PROJECT_ROOT / "json_results" / "cleaning_report.json"
WORKSPACE_REPORT_PATH = PROJECT_ROOT / "Reports" / "cleaning_report.json"

OUT_DIR.mkdir(parents=True, exist_ok=True)
JSON_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
WORKSPACE_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

# ── Constants ──────────────────────────────────────────────────────────────────
INF_COLS = ["Flow Bytes/s", "Flow Packets/s"]   # only cols with Inf (from Step 1)
NAN_COL = "Flow Bytes/s"                        # only col with NaN (from Step 1)

# ── Helper ─────────────────────────────────────────────────────────────────────
def count_nan(df):
    return int(df.isnull().sum().sum())

def count_pos_inf_total(df):
    total = 0
    for c in df.select_dtypes(include=[float]).columns:
        total += int(np.isposinf(df[c]).sum())
    return total

def count_neg_inf_total(df):
    total = 0
    for c in df.select_dtypes(include=[float]).columns:
        total += int(np.isneginf(df[c]).sum())
    return total

# ── Per-file cleaning ──────────────────────────────────────────────────────────
all_results = []

csv_files = sorted(RAW_DIR.glob("*.csv"))
if not csv_files:
    print(f"ERROR: No CSV files found in {RAW_DIR}", file=sys.stderr)
    sys.exit(1)

print(f"Found {len(csv_files)} CSV files.\n")
print("=" * 72)

for csv_path in csv_files:
    fname = csv_path.name
    print(f"\n{'-'*72}")
    print(f"Processing: {fname}")
    print(f"{'-'*72}")

    # ── Load ───────────────────────────────────────────────────────────────────
    df = pd.read_csv(csv_path, low_memory=False, encoding="utf-8", encoding_errors="replace")
    df.columns = df.columns.str.strip()

    orig_rows = len(df)
    print(f"  Original rows      : {orig_rows:>10,}")

    # ── Step 1: Fix Web Attack label Unicode artifact ──────────────────────────
    labels_before = df["Label"].value_counts().to_dict()
    df["Label"] = df["Label"].str.replace("\ufffd", "\u2013", regex=False)
    labels_after = df["Label"].value_counts().to_dict()
    unicode_fixed = labels_before != labels_after
    print(f"  Label Unicode fix  : {'applied' if unicode_fixed else 'not needed (no \\ufffd found)'}")

    # ── Step 2: Capture pre-clean quality metrics ──────────────────────────────
    pre_nan = count_nan(df)
    pre_pos_inf = count_pos_inf_total(df)
    pre_neg_inf = count_neg_inf_total(df)
    pre_dups = int(df.duplicated().sum())

    print(f"  Pre-clean NaN      : {pre_nan:>10,}")
    print(f"  Pre-clean +Inf     : {pre_pos_inf:>10,}")
    print(f"  Pre-clean -Inf     : {pre_neg_inf:>10,}")
    print(f"  Pre-clean dups     : {pre_dups:>10,}")

    # ── Step 3: Replace +Inf / -Inf in rate columns with NaN ──────────────────
    for col in INF_COLS:
        if col in df.columns:
            df[col] = df[col].replace([np.inf, -np.inf], np.nan)

    # ── Step 4: Remove zero-duration rows ─────────────────────────────────────
    zero_dur_mask = (df["Flow Duration"] == 0)
    zero_dur_count = int(zero_dur_mask.sum())

    nan_in_zero_dur = int(df.loc[zero_dur_mask, NAN_COL].isnull().sum()) if NAN_COL in df.columns else 0

    df = df[~zero_dur_mask].reset_index(drop=True)
    rows_after_zero_dur = len(df)
    removed_zero_dur = orig_rows - rows_after_zero_dur

    print(f"  Flow Duration==0   : {zero_dur_count:>10,}  (removed — malformed flows)")
    print(f"    NaN in those rows: {nan_in_zero_dur:>10,}")

    # ── Step 5: Safety check for remaining NaN/Inf ────────────────────────────
    remaining_nan = count_nan(df)
    remaining_pos_inf = count_pos_inf_total(df)
    remaining_neg_inf = count_neg_inf_total(df)

    extra_removed_nan = 0
    if remaining_nan > 0 or remaining_pos_inf > 0 or remaining_neg_inf > 0:
        print(f"  WARNING: Residual NaN={remaining_nan}, +Inf={remaining_pos_inf}, -Inf={remaining_neg_inf}")
        float_cols = df.select_dtypes(include=[float]).columns
        bad_mask = df[float_cols].isnull().any(axis=1)
        for col in float_cols:
            bad_mask |= np.isinf(df[col])
        extra_removed_nan = int(bad_mask.sum())
        df = df[~bad_mask].reset_index(drop=True)
        print(f"  Extra rows removed : {extra_removed_nan:>10,}")

    # ── Step 6: Remove exact duplicate rows ───────────────────────────────────
    df_before_dedup = len(df)
    df = df.drop_duplicates(keep="first")
    df = df.reset_index(drop=True)
    removed_dups = df_before_dedup - len(df)
    print(f"  Duplicates removed : {removed_dups:>10,}")

    final_rows = len(df)

    # ── Step 7: Final quality verification ────────────────────────────────────
    final_nan = count_nan(df)
    final_pos_inf = count_pos_inf_total(df)
    final_neg_inf = count_neg_inf_total(df)
    final_dups = int(df.duplicated().sum())

    print(f"  Final rows         : {final_rows:>10,}")
    print(f"  Final NaN          : {final_nan:>10,}  {'✓' if final_nan == 0 else '✗ WARN'}")
    print(f"  Final +Inf         : {final_pos_inf:>10,}  {'✓' if final_pos_inf == 0 else '✗ WARN'}")
    print(f"  Final -Inf         : {final_neg_inf:>10,}  {'✓' if final_neg_inf == 0 else '✗ WARN'}")
    print(f"  Final dups         : {final_dups:>10,}  {'✓' if final_dups == 0 else '✗ WARN'}")

    final_labels = df["Label"].value_counts().to_dict()

    # ── Step 8: Save output ────────────────────────────────────────────────────
    out_path = OUT_DIR / f"cleaned_{fname}"
    df.to_csv(out_path, index=False, encoding="utf-8")
    out_size_mb = out_path.stat().st_size / (1024 * 1024)
    print(f"  Saved -> processed/cleaned_{fname}  ({out_size_mb:.2f} MB)")

    all_results.append({
        "file": fname,
        "original_rows": orig_rows,
        "removed_zero_duration": removed_zero_dur,
        "removed_extra_nan_inf": extra_removed_nan,
        "removed_duplicates": removed_dups,
        "total_removed": orig_rows - final_rows,
        "final_rows": final_rows,
        "pct_removed": round((orig_rows - final_rows) / orig_rows * 100, 3),
        "final_nan": final_nan,
        "final_pos_inf": final_pos_inf,
        "final_neg_inf": final_neg_inf,
        "final_duplicates": final_dups,
        "label_distribution_after": final_labels,
        "unicode_label_fix_applied": unicode_fixed,
        "output_file": str(out_path),
    })

# ── Overall summary ────────────────────────────────────────────────────────────
print("\n" + "=" * 72)
print("OVERALL SUMMARY")
print("=" * 72)

total_original = sum(r["original_rows"] for r in all_results)
total_removed_zerodur = sum(r["removed_zero_duration"] for r in all_results)
total_removed_extra = sum(r["removed_extra_nan_inf"] for r in all_results)
total_removed_dups = sum(r["removed_duplicates"] for r in all_results)
total_final = sum(r["final_rows"] for r in all_results)
total_removed = total_original - total_final

print(f"  Total original rows         : {total_original:>10,}")
print(f"  Removed (zero-duration/NaN) : {total_removed_zerodur:>10,}")
print(f"  Removed (extra NaN/Inf)     : {total_removed_extra:>10,}")
print(f"  Removed (duplicates)        : {total_removed_dups:>10,}")
print(f"  Total rows removed          : {total_removed:>10,}  ({total_removed/total_original*100:.3f}%)")
print(f"  Final row count             : {total_final:>10,}")
print(f"  Remaining NaN               : {sum(r['final_nan'] for r in all_results):>10,}")
print(f"  Remaining +Inf              : {sum(r['final_pos_inf'] for r in all_results):>10,}")
print(f"  Remaining -Inf              : {sum(r['final_neg_inf'] for r in all_results):>10,}")
print(f"  Remaining duplicates        : {sum(r['final_duplicates'] for r in all_results):>10,}")

summary = {
    "timestamp": datetime.now().isoformat(),
    "step": "Step 2 — Data Cleaning",
    "totals": {
        "original_rows": total_original,
        "removed_zero_duration_rows": total_removed_zerodur,
        "removed_extra_nan_inf_rows": total_removed_extra,
        "removed_duplicate_rows": total_removed_dups,
        "total_removed": total_removed,
        "final_rows": total_final,
        "pct_removed": round(total_removed / total_original * 100, 3),
        "remaining_nan": sum(r["final_nan"] for r in all_results),
        "remaining_pos_inf": sum(r["final_pos_inf"] for r in all_results),
        "remaining_neg_inf": sum(r["final_neg_inf"] for r in all_results),
        "remaining_duplicates": sum(r["final_duplicates"] for r in all_results),
    },
    "per_file": all_results,
}

with open(JSON_REPORT_PATH, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)

with open(WORKSPACE_REPORT_PATH, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)

print(f"\nJSON report saved -> {JSON_REPORT_PATH} and {WORKSPACE_REPORT_PATH}")
print("\nStep 2 complete. Raw data has NOT been modified.")
