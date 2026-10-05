# -*- coding: utf-8 -*-
"""
Step 1: Inspect the CSE-CIC-IDS2018 Dataset
===========================================
Performs a read-only inspection of the raw CSV files:
- Schema verification & column data types
- Missing (NaN) values per column
- Infinity values (+Inf, -Inf)
- Duplicate row counts
- Label frequency distribution
- Timestamp identification and order check
- First 5 rows snapshot
"""

import os
import sys
import io
import json
import warnings
from pathlib import Path
import pandas as pd
import numpy as np

# Force UTF-8 output streams for Windows consoles
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

warnings.filterwarnings("ignore")

# ── Paths ──────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "MachineLearningCVE"
OUT_FILE = PROJECT_ROOT / "json_results" / "inspection_results.json"
REPORTS_OUT = PROJECT_ROOT / "Reports" / "inspection_results.json"

OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
REPORTS_OUT.parent.mkdir(parents=True, exist_ok=True)

files = sorted([f for f in os.listdir(DATA_DIR) if f.endswith(".csv")])

all_results = []
overall = {
    "total_files": len(files),
    "total_rows": 0,
    "total_missing": 0,
    "total_inf": 0,
    "total_duplicates": 0,
    "label_distribution": {},
    "column_set_consistent": True,
    "first_file_cols": None,
}

for fname in files:
    fpath = DATA_DIR / fname
    fsize_mb = fpath.stat().st_size / (1024 * 1024)

    print(f"\n{'='*70}")
    print(f"Processing: {fname}  ({fsize_mb:.2f} MB)")

    # Load CSV
    df = pd.read_csv(fpath, low_memory=False)

    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    n_rows, n_cols = df.shape

    # Data types
    dtypes = {col: str(df[col].dtype) for col in df.columns}

    # Missing values per column
    missing = df.isnull().sum().to_dict()
    missing_serializable = {k: int(v) for k, v in missing.items()}
    total_missing_file = int(df.isnull().sum().sum())

    # Infinity values per column (numeric only)
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    pos_inf = {}
    neg_inf = {}
    for col in numeric_cols:
        pos_inf[col] = int((df[col] == np.inf).sum())
        neg_inf[col] = int((df[col] == -np.inf).sum())

    total_pos_inf = sum(pos_inf.values())
    total_neg_inf = sum(neg_inf.values())

    # Duplicate rows
    n_duplicates = int(df.duplicated().sum())

    # Label column
    label_col = None
    for c in df.columns:
        if c.strip().lower() == "label":
            label_col = c
            break

    label_info = {}
    if label_col:
        vc = df[label_col].value_counts(dropna=False)
        label_info = {str(k): int(v) for k, v in vc.items()}

    # Timestamp column detection
    ts_col = None
    ts_candidates = [
        c
        for c in df.columns
        if "timestamp" in c.lower() or "time" in c.lower() or "date" in c.lower()
    ]
    if ts_candidates:
        ts_col = ts_candidates[0]

    ts_info = {}
    if ts_col:
        ts_series = df[ts_col]
        ts_info = {
            "column_name": ts_col,
            "dtype": str(ts_series.dtype),
            "first_5": [str(v) for v in ts_series.head(5).tolist()],
            "last_5": [str(v) for v in ts_series.tail(5).tolist()],
        }
        try:
            ts_parsed = pd.to_datetime(ts_series, infer_datetime_format=True, errors="coerce")
            ts_valid = ts_parsed.dropna()
            if len(ts_valid) > 1:
                is_sorted = bool(ts_valid.is_monotonic_increasing)
            else:
                is_sorted = True
            ts_info["chronologically_ordered"] = is_sorted
            ts_info["first_5_parsed"] = [str(v) for v in ts_parsed.head(5).tolist()]
            ts_info["last_5_parsed"] = [str(v) for v in ts_parsed.tail(5).tolist()]
        except Exception as e:
            ts_info["chronologically_ordered"] = f"Could not determine: {e}"

    # First 5 rows
    first5 = df.head(5).astype(str).to_dict(orient="records")

    result = {
        "file_name": fname,
        "file_size_mb": round(fsize_mb, 2),
        "n_rows": n_rows,
        "n_cols": n_cols,
        "column_names": list(df.columns),
        "dtypes": dtypes,
        "missing_per_column": missing_serializable,
        "total_missing": total_missing_file,
        "pos_inf_per_column": {k: v for k, v in pos_inf.items() if v > 0},
        "neg_inf_per_column": {k: v for k, v in neg_inf.items() if v > 0},
        "total_pos_inf": total_pos_inf,
        "total_neg_inf": total_neg_inf,
        "n_duplicates": n_duplicates,
        "label_distribution": label_info,
        "timestamp_info": ts_info,
        "first_5_rows": first5,
    }

    all_results.append(result)

    # Update overall
    overall["total_rows"] += n_rows
    overall["total_missing"] += total_missing_file
    overall["total_inf"] += total_pos_inf + total_neg_inf
    overall["total_duplicates"] += n_duplicates
    for k, v in label_info.items():
        overall["label_distribution"][k] = overall["label_distribution"].get(k, 0) + v

    if overall["first_file_cols"] is None:
        overall["first_file_cols"] = list(df.columns)
    elif overall["first_file_cols"] != list(df.columns):
        overall["column_set_consistent"] = False

    print(
        f"  Rows: {n_rows:,}  Cols: {n_cols}  Missing: {total_missing_file:,}  "
        f"+Inf: {total_pos_inf:,}  -Inf: {total_neg_inf:,}  Dups: {n_duplicates:,}"
    )

output = {"files": all_results, "overall": overall}

with open(OUT_FILE, "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2, default=str)

with open(REPORTS_OUT, "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2, default=str)

print(f"\n\nResults saved to: {OUT_FILE} and {REPORTS_OUT}")
print("DONE")
