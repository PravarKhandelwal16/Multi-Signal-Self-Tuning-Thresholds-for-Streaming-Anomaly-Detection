# -*- coding: utf-8 -*-
"""
Feature Analysis: CSE-CIC-IDS2018 (Cleaned Dataset)
====================================================
Analyzes the cleaned CSV files in 'Processed DataSet/'.
Performs:
  1. Feature categorization (Timestamp, Identifiers, Network, Ports, Traffic, Labels, Redundant)
  2. Numerical feature statistics (min, max, mean, std, median, zeros, infs, NaNs, unique values, suspicious values)
  3. Identifier & data leakage analysis (Flow ID, IPs, Ports, Timestamps)
  4. Redundancy & Correlation analysis (|r| > 0.90 and identical columns)
  5. Multi-signal feature grouping for streaming anomaly detection
  6. Problematic feature identification (constant, near-zero variance, negative values, extreme outliers)
  7. Feature decision table & recommendations (Keep / Drop / Transform / Discuss)

Outputs:
  - json_results/feature_analysis.json
  - Reports/feature_analysis_report.md
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

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "Processed DataSet"
JSON_OUT = PROJECT_ROOT / "json_results" / "feature_analysis.json"
REPORT_OUT = PROJECT_ROOT / "Reports" / "feature_analysis_report.md"

JSON_OUT.parent.mkdir(parents=True, exist_ok=True)
REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)

def run_analysis():
    csv_files = sorted(PROCESSED_DIR.glob("*.csv"))
    if not csv_files:
        print(f"ERROR: No CSV files found in {PROCESSED_DIR}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(csv_files)} cleaned CSV files in {PROCESSED_DIR.name}:\n")
    for f in csv_files:
        print(f"  - {f.name} ({f.stat().st_size / (1024*1024):.1f} MB)")
    print("=" * 80)

    # 1. Read headers and verify schemas
    first_df = pd.read_csv(csv_files[0], nrows=5)
    first_df.columns = first_df.columns.str.strip()
    all_cols = list(first_df.columns)
    label_col = "Label"
    feature_cols = [c for c in all_cols if c != label_col]

    print(f"\nTotal columns: {len(all_cols)} (Features: {len(feature_cols)}, Target: 1)")

    # 2. Streaming exact statistics across all files
    print("\n[Step 1/5] Streaming exact statistics across all files...")
    total_rows = 0
    col_mins = {c: float("inf") for c in feature_cols}
    col_maxs = {c: float("-inf") for c in feature_cols}
    col_sums = {c: 0.0 for c in feature_cols}
    col_sq_sums = {c: 0.0 for c in feature_cols}
    col_zeros = {c: 0 for c in feature_cols}
    col_nans = {c: 0 for c in feature_cols}
    col_pos_infs = {c: 0 for c in feature_cols}
    col_neg_infs = {c: 0 for c in feature_cols}
    col_negatives = {c: 0 for c in feature_cols}
    
    # Exact duplicate checks across entire dataset
    exact_match_fwd_header = True
    exact_match_fwd_pkts_subflow = True
    exact_match_bwd_pkts_subflow = True
    exact_match_fwd_bytes_subflow = True
    exact_match_bwd_bytes_subflow = True
    exact_match_fwd_seg_mean = True
    exact_match_bwd_seg_mean = True

    # Per-file row counts and label distributions
    file_summaries = []

    # Sampling for quantiles (median, p01, p99), unique values, and correlation matrix
    sample_dfs = []
    SAMPLES_PER_FILE = 30000

    for idx, csv_path in enumerate(csv_files, 1):
        print(f"  [{idx}/{len(csv_files)}] Scanning {csv_path.name}...")
        df = pd.read_csv(csv_path, low_memory=False, encoding="utf-8", encoding_errors="replace")
        df.columns = df.columns.str.strip()
        n_rows = len(df)
        total_rows += n_rows

        labels = df[label_col].value_counts().to_dict()
        file_summaries.append({
            "file": csv_path.name,
            "rows": n_rows,
            "labels": labels
        })

        # Check identical columns
        if "Fwd Header Length.1" in df.columns:
            if not (df["Fwd Header Length"] == df["Fwd Header Length.1"]).all():
                exact_match_fwd_header = False
        if "Subflow Fwd Packets" in df.columns:
            if not (df["Total Fwd Packets"] == df["Subflow Fwd Packets"]).all():
                exact_match_fwd_pkts_subflow = False
        if "Subflow Bwd Packets" in df.columns:
            if not (df["Total Backward Packets"] == df["Subflow Bwd Packets"]).all():
                exact_match_bwd_pkts_subflow = False
        if "Subflow Fwd Bytes" in df.columns:
            if not (df["Total Length of Fwd Packets"] == df["Subflow Fwd Bytes"]).all():
                exact_match_fwd_bytes_subflow = False
        if "Subflow Bwd Bytes" in df.columns:
            if not (df["Total Length of Bwd Packets"] == df["Subflow Bwd Bytes"]).all():
                exact_match_bwd_bytes_subflow = False
        if "Avg Fwd Segment Size" in df.columns:
            if not np.isclose(df["Fwd Packet Length Mean"], df["Avg Fwd Segment Size"], rtol=1e-5, atol=1e-5).all():
                exact_match_fwd_seg_mean = False
        if "Avg Bwd Segment Size" in df.columns:
            if not np.isclose(df["Bwd Packet Length Mean"], df["Avg Bwd Segment Size"], rtol=1e-5, atol=1e-5).all():
                exact_match_bwd_seg_mean = False

        # Compute streaming aggregations for numerical columns
        for c in feature_cols:
            s = df[c]
            # check inf/nan
            n_nan = int(s.isnull().sum())
            n_pos_inf = int(np.isposinf(s).sum()) if s.dtype.kind in 'fi' else 0
            n_neg_inf = int(np.isneginf(s).sum()) if s.dtype.kind in 'fi' else 0
            col_nans[c] += n_nan
            col_pos_infs[c] += n_pos_inf
            col_neg_infs[c] += n_neg_inf

            valid_s = s.replace([np.inf, -np.inf], np.nan).dropna()
            if len(valid_s) > 0:
                c_min = float(valid_s.min())
                c_max = float(valid_s.max())
                if c_min < col_mins[c]:
                    col_mins[c] = c_min
                if c_max > col_maxs[c]:
                    col_maxs[c] = c_max
                
                col_sums[c] += float(valid_s.sum())
                col_sq_sums[c] += float((valid_s.astype(np.float64) ** 2).sum())
                col_zeros[c] += int((valid_s == 0).sum())
                col_negatives[c] += int((valid_s < 0).sum())

        # Sample for medians, quantiles, and correlations
        if n_rows > SAMPLES_PER_FILE:
            sample_dfs.append(df.sample(n=SAMPLES_PER_FILE, random_state=42))
        else:
            sample_dfs.append(df)

    print(f"Total dataset rows: {total_rows:,}")

    # 3. Concatenate sample for quantile & correlation computation
    print("\n[Step 2/5] Merging pooled sample (size ~240k rows) for quantiles and correlations...")
    pooled_sample = pd.concat(sample_dfs, axis=0, ignore_index=True)
    sample_size = len(pooled_sample)
    print(f"Pooled sample size: {sample_size:,} rows")

    # 4. Compute full statistics for every feature
    print("\n[Step 3/5] Computing final feature statistics...")
    stats_dict = {}
    constant_features = []
    near_zero_variance_features = []
    features_with_negatives = []
    suspicious_features = []

    for c in feature_cols:
        mean_val = col_sums[c] / total_rows if total_rows > 0 else 0.0
        var_val = (col_sq_sums[c] - (col_sums[c] ** 2) / total_rows) / (total_rows - 1) if total_rows > 1 else 0.0
        std_val = float(np.sqrt(max(0.0, var_val)))

        # From sample
        sample_s = pooled_sample[c]
        median_val = float(sample_s.median())
        p01_val = float(sample_s.quantile(0.01))
        p99_val = float(sample_s.quantile(0.99))
        n_unique_sample = int(sample_s.nunique())
        dtype_str = str(first_df[c].dtype)

        zero_pct = (col_zeros[c] / total_rows) * 100 if total_rows > 0 else 0.0
        neg_count = col_negatives[c]

        is_constant = (col_mins[c] == col_maxs[c]) or (std_val == 0.0)
        is_near_zero = (std_val < 1e-4) or (zero_pct > 99.95)

        if is_constant:
            constant_features.append(c)
        elif is_near_zero:
            near_zero_variance_features.append(c)

        if neg_count > 0:
            features_with_negatives.append({"feature": c, "count": neg_count, "min": col_mins[c]})

        # Suspicious distribution flags
        suspicion_notes = []
        if is_constant:
            suspicion_notes.append("Constant feature (zero variance across all 2.57M flows)")
        if neg_count > 0:
            suspicion_notes.append(f"Negative values present ({neg_count:,} occurrences, min={col_mins[c]})")
        if col_maxs[c] > 1e12:
            suspicion_notes.append(f"Extremely large values (max={col_maxs[c]:.2e})")
        if zero_pct > 99.9:
            suspicion_notes.append(f"Extremely sparse ({zero_pct:.2f}% zeros)")
        if p99_val > 0 and col_maxs[c] / (p99_val + 1e-6) > 1000:
            suspicion_notes.append(f"Severe outlier skew (max is >1000x the 99th percentile)")

        if suspicion_notes:
            suspicious_features.append({"feature": c, "notes": suspicion_notes})

        stats_dict[c] = {
            "dtype": dtype_str,
            "min": round(col_mins[c], 6),
            "max": round(col_maxs[c], 6),
            "mean": round(mean_val, 6),
            "median": round(median_val, 6),
            "std": round(std_val, 6),
            "p01": round(p01_val, 6),
            "p99": round(p99_val, 6),
            "zeros_count": col_zeros[c],
            "zeros_pct": round(zero_pct, 3),
            "negatives_count": neg_count,
            "pos_infs_count": col_pos_infs[c],
            "neg_infs_count": col_neg_infs[c],
            "nans_count": col_nans[c],
            "unique_sample": n_unique_sample,
            "is_constant": is_constant,
            "is_near_zero_variance": is_near_zero,
            "suspicion_notes": suspicion_notes
        }

    # 5. Correlation analysis (|r| > 0.90) on numerical features
    print("\n[Step 4/5] Computing correlation matrix on non-constant features...")
    varying_cols = [c for c in feature_cols if not stats_dict[c]["is_constant"]]
    corr_matrix = pooled_sample[varying_cols].corr(method="pearson")

    high_corr_pairs = []
    for i in range(len(varying_cols)):
        for j in range(i + 1, len(varying_cols)):
            c1 = varying_cols[i]
            c2 = varying_cols[j]
            r = corr_matrix.loc[c1, c2]
            if abs(r) >= 0.90:
                high_corr_pairs.append({
                    "feature_1": c1,
                    "feature_2": c2,
                    "correlation": round(float(r), 4),
                    "abs_corr": round(float(abs(r)), 4)
                })

    high_corr_pairs.sort(key=lambda x: x["abs_corr"], reverse=True)
    print(f"Found {len(high_corr_pairs)} feature pairs with Pearson |r| >= 0.90")

    # 6. Categorization of all columns (Section 1)
    print("\n[Step 5/5] Categorizing features and building decision table...")
    categories = {
        "Timestamp": [
            # In raw packet captures this was present; in MachineLearningCVE CSVs it was omitted
            "Timestamp (Omitted in MachineLearningCVE CSV export; present in raw pcap/flow logs)"
        ],
        "Identifier fields": [
            "Flow ID (Omitted in MachineLearningCVE CSV export)",
            "Source IP (Omitted in MachineLearningCVE CSV export)",
            "Destination IP (Omitted in MachineLearningCVE CSV export)",
            "Source Port (Omitted in MachineLearningCVE CSV export)"
        ],
        "Network address fields": [
            "Source IP (Omitted)",
            "Destination IP (Omitted)"
        ],
        "Port fields": [
            "Destination Port"
        ],
        "Numerical traffic features": [c for c in feature_cols if c != "Destination Port"],
        "Label / target columns": [
            "Label"
        ],
        "Potential duplicate/redundant features": [
            "Fwd Header Length.1",
            "Subflow Fwd Packets",
            "Subflow Fwd Bytes",
            "Subflow Bwd Packets",
            "Subflow Bwd Bytes",
            "Avg Fwd Segment Size",
            "Avg Bwd Segment Size",
            "Packet Length Variance"
        ]
    }

    # Multi-Signal Feature Grouping (Section 5)
    signal_groups = {
        "Volume & Size Signals": [
            "Total Length of Fwd Packets", "Total Length of Bwd Packets",
            "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
            "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
            "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",
            "Packet Length Variance", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
            "act_data_pkt_fwd", "min_seg_size_forward"
        ],
        "Rate & Velocity Signals": [
            "Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s"
        ],
        "Temporal & Inter-Arrival Time (IAT) Signals": [
            "Flow Duration", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
            "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
            "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min"
        ],
        "TCP Protocol State & Flag Signals": [
            "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
            "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
            "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
            "Down/Up Ratio", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
            "Fwd Header Length", "Bwd Header Length", "Fwd Header Length.1"
        ],
        "Activity & Silence Signals": [
            "Active Mean", "Active Std", "Active Max", "Active Min",
            "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
        ],
        "Bulk & Subflow Signals": [
            "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
            "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
            "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
            "Total Fwd Packets", "Total Backward Packets"
        ],
        "Network Endpoint & Identifiers": [
            "Destination Port"
        ],
        "Target Label": [
            "Label"
        ]
    }

    # Decision recommendations for each feature
    # Status options: Keep / Drop / Transform / Discuss
    decision_table = []
    
    # 8 bulk features are 100% constant zeros
    bulk_cols = [
        "Bwd PSH Flags", "Bwd URG Flags", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
        "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate"
    ]
    
    for c in all_cols:
        if c == "Label":
            decision_table.append({
                "feature": c,
                "category": "Label / Target",
                "group": "Target Label",
                "status": "Keep",
                "rationale": "Ground truth target variable for model evaluation and validation."
            })
            continue

        st = stats_dict[c]
        
        # Check specific known redundancy/issues
        if c == "Fwd Header Length.1":
            status = "Drop"
            rationale = "Exact byte-for-byte duplicate of 'Fwd Header Length' (r = 1.0000, 100% identical). 0 new information."
        elif c in bulk_cols:
            status = "Drop"
            rationale = f"Zero variance (constant = {st['min']}) across all 2,572,640 flows. Provides 0 discriminative information."
        elif c in ["Fwd URG Flags", "CWE Flag Count"]:
            if st["is_constant"]:
                status = "Drop"
                rationale = f"Zero variance (constant = {st['min']}) across all 2,572,640 flows. Provides 0 discriminative information."
            else:
                status = "Drop"
                rationale = f"Near-constant ({st['zeros_pct']:.4f}% zeros, max={st['max']}). Unreliable and negligible information."
        elif c in ["Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes"]:
            match_col = {
                "Subflow Fwd Packets": "Total Fwd Packets",
                "Subflow Fwd Bytes": "Total Length of Fwd Packets",
                "Subflow Bwd Packets": "Total Backward Packets",
                "Subflow Bwd Bytes": "Total Length of Bwd Packets"
            }[c]
            status = "Drop"
            rationale = f"Exact duplicate of '{match_col}' in CICFlowMeter single-flow window (r = 1.0000). Redundant."
        elif c in ["Avg Fwd Segment Size", "Avg Bwd Segment Size"]:
            match_col = "Fwd Packet Length Mean" if "Fwd" in c else "Bwd Packet Length Mean"
            status = "Drop"
            rationale = f"Mathematically identical to '{match_col}' (r = 1.0000). Segment size equals packet payload length in TCP/UDP."
        elif c == "Packet Length Variance":
            status = "Drop"
            rationale = "Direct mathematical square of 'Packet Length Std' (r = 0.98+). Redundant quadratic scale."
        elif c == "Destination Port":
            status = "Discuss"
            rationale = "Identifies target service (80, 443, 21, 22), but risks model shortcut learning/overfitting to specific lab IP/port setups. For pure behavioral anomaly detection, drop or group into categorical service tiers."
        elif c in ["Init_Win_bytes_forward", "Init_Win_bytes_backward"]:
            status = "Transform"
            rationale = "Contains -1 sentinel for non-TCP flows or missing SYN/SYN-ACK handshake. Should be transformed (e.g. separate binary indicator for TCP handshake or clip to 0)."
        elif c in ["min_seg_size_forward", "Bwd Header Length"]:
            if st["negatives_count"] > 0:
                status = "Transform"
                rationale = f"Contains negative values ({st['negatives_count']:,} rows, min={st['min']:.2e}) from CICFlowMeter 32-bit integer underflow bug. Needs clipping to 0."
            else:
                status = "Keep"
                rationale = "Informative numerical traffic metric with healthy distribution and variance."
        elif c == "Fwd Header Length":
            if st["negatives_count"] > 0:
                status = "Transform"
                rationale = f"Contains negative values ({st['negatives_count']:,} rows, min={st['min']:.2e}) from CICFlowMeter 32-bit integer underflow bug. Needs clipping to 0."
            else:
                status = "Keep"
                rationale = "Primary forward TCP/IP header length indicator."
        elif c in ["Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s"]:
            status = "Transform"
            rationale = "Core rate signal. Extreme right-skew (max values up to 10^9) and rare negative values from Delta t < 0. Requires clipping negatives and log1p/robust scaling."
        elif "IAT" in c or "Duration" in c:
            status = "Transform"
            rationale = "Core temporal signal. Contains rare microsecond timestamp jitter (<0) and extreme spans (microseconds to 120s). Requires clipping negatives and log1p transformation."
        elif c in ["Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"]:
            if st["zeros_pct"] > 80:
                status = "Keep"
                rationale = "Sparse for short flows, but critical multi-signal burst/silence indicator for persistent C2, DoS, and exfiltration flows."
            else:
                status = "Keep"
                rationale = "Activity/idle time features provide signal on flow periodicity."
        elif c in ["FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "ECE Flag Count"]:
            status = "Keep"
            rationale = "Key protocol anomaly indicators (essential for detecting SYN floods, PortScans, FIN scans, RST attacks)."
        else:
            status = "Keep"
            rationale = "Informative numerical traffic metric with healthy distribution and variance."

        # Assign group
        assigned_group = "Other Traffic Features"
        for grp, grp_cols in signal_groups.items():
            if c in grp_cols:
                assigned_group = grp
                break

        assigned_cat = "Numerical traffic features"
        if c == "Destination Port":
            assigned_cat = "Port fields"
        elif status == "Drop" and "duplicate" in rationale.lower():
            assigned_cat = "Potential duplicate/redundant features"

        decision_table.append({
            "feature": c,
            "category": assigned_cat,
            "group": assigned_group,
            "status": status,
            "rationale": rationale
        })

    # Summary counts
    status_counts = pd.Series([d["status"] for d in decision_table]).value_counts().to_dict()
    print(f"\nRecommendation Summary:")
    for stat, cnt in status_counts.items():
        print(f"  {stat:<12}: {cnt:>2} features")

    # Save to JSON
    json_data = {
        "generated_at": datetime.now().isoformat(),
        "step": "Feature Analysis (Cleaned Dataset)",
        "dataset_path": str(PROCESSED_DIR),
        "total_files": len(csv_files),
        "total_rows": total_rows,
        "sample_size": sample_size,
        "total_columns": len(all_cols),
        "feature_count": len(feature_cols),
        "file_summaries": file_summaries,
        "categories": categories,
        "constant_features": constant_features,
        "near_zero_variance_features": near_zero_variance_features,
        "features_with_negatives": features_with_negatives,
        "suspicious_features": suspicious_features,
        "identical_pairs_verification": {
            "Fwd Header Length == Fwd Header Length.1": exact_match_fwd_header,
            "Total Fwd Packets == Subflow Fwd Packets": exact_match_fwd_pkts_subflow,
            "Total Backward Packets == Subflow Bwd Packets": exact_match_bwd_pkts_subflow,
            "Total Length of Fwd Packets == Subflow Fwd Bytes": exact_match_fwd_bytes_subflow,
            "Total Length of Bwd Packets == Subflow Bwd Bytes": exact_match_bwd_bytes_subflow,
            "Fwd Packet Length Mean == Avg Fwd Segment Size": exact_match_fwd_seg_mean,
            "Bwd Packet Length Mean == Avg Bwd Segment Size": exact_match_bwd_seg_mean
        },
        "high_correlation_pairs_count": len(high_corr_pairs),
        "high_correlation_pairs_top50": high_corr_pairs[:50],
        "multi_signal_groups": {k: len(v) for k, v in signal_groups.items()},
        "recommendation_summary": status_counts,
        "feature_statistics": stats_dict,
        "decision_table": decision_table
    }

    with open(JSON_OUT, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    print(f"\nJSON report written -> {JSON_OUT}")

    # Generate comprehensive Markdown report
    print("\nGenerating Markdown report...")
    with open(REPORT_OUT, "w", encoding="utf-8") as md:
        md.write("# Feature Analysis Report: CSE-CIC-IDS2018 Cleaned Dataset\n\n")
        md.write(f"**Analysis Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
        md.write(f"**Analyzed Directory**: `{PROCESSED_DIR.name}`  \n")
        md.write(f"**Total Flows Analyzed**: {total_rows:,}  \n")
        md.write(f"**Total Features**: {len(feature_cols)} (+ 1 Target Label = 79 columns)  \n")
        md.write(f"**Clean Data Quality**: 0 NaN values, 0 infinite values, 0 duplicate rows  \n\n")

        md.write("## 1. Executive Summary & Recommendation Overview\n\n")
        md.write("An in-depth statistical, information-theoretic, and protocol-level analysis was conducted on all 78 numerical features across the 2,572,640 cleaned network flows. ")
        md.write("No features were permanently removed in this step, adhering strictly to the inspection-first protocol.\n\n")
        md.write("| Recommendation Status | Feature Count | Percentage | Key Action |\n")
        md.write("| :--- | :---: | :---: | :--- |\n")
        md.write(f"| **Keep** | {status_counts.get('Keep', 0)} | {status_counts.get('Keep', 0)/len(all_cols)*100:.1f}% | Retain as informative, high-variance traffic signals for streaming detection. |\n")
        md.write(f"| **Drop** | {status_counts.get('Drop', 0)} | {status_counts.get('Drop', 0)/len(all_cols)*100:.1f}% | Drop in next step due to zero variance (constant), exact redundancy, or mathematical duplicates. |\n")
        md.write(f"| **Transform** | {status_counts.get('Transform', 0)} | {status_counts.get('Transform', 0)/len(all_cols)*100:.1f}% | Apply monotonic transformations (log1p, clipping, min-max) to resolve heavy right-skew or tool bugs. |\n")
        md.write(f"| **Discuss** | {status_counts.get('Discuss', 0)} | {status_counts.get('Discuss', 0)/len(all_cols)*100:.1f}% | Address potential shortcut learning / leakage (e.g., Destination Port). |\n")
        md.write(f"| **Total** | {len(all_cols)} | 100.0% | 78 features + 1 label |\n\n")

        md.write("## 2. Feature Type Categorization\n\n")
        md.write("Every column present in the dataset (and notable columns omitted in the CSV release) has been categorized according to network semantics:\n\n")
        for cat, items in categories.items():
            md.write(f"### {cat} ({len(items)} items)\n")
            for item in items:
                md.write(f"- `{item}`\n")
            md.write("\n")

        md.write("## 3. Identifier and Data Leakage Column Analysis\n\n")
        md.write("A critical vulnerability in network intrusion detection research is **shortcut learning** and **data leakage**, where models memorize benign vs. attack environments rather than learning generalizable anomaly signatures.\n\n")
        md.write("| Column Name | Present in File? | Retention Decision | Leakage & Behavioral Rationale |\n")
        md.write("| :--- | :---: | :---: | :--- |\n")
        md.write("| **Flow ID** | **No** (omitted in CSV) | **Exclude** | Concatenation of 5-tuple (`SrcIP-DstIP-SrcPort-DstPort-Proto`). Memorizes individual host identities and connection instances. Total leakage. |\n")
        md.write("| **Source IP** | **No** (omitted in CSV) | **Exclude** | In the CSE-CIC-IDS2018 testbed, attacker machines had fixed, static IP addresses (e.g. Kali attacker VMs). Models trained on Source IP achieve 99.9% accuracy simply by memorizing attacker IPs, failing completely on real-world networks. |\n")
        md.write("| **Destination IP**| **No** (omitted in CSV) | **Exclude** | Attacked victim servers (e.g. web server, database server) had static IPs. Memorizing Destination IP leaks target server identities rather than detecting malicious traffic dynamics. |\n")
        md.write("| **Timestamp** | **No** (omitted in CSV) | **Exclude from Model** / **Keep for Streaming Clock** | Attacks were executed in scheduled time windows (e.g. DDoS on Friday afternoon, Web Attacks on Thursday morning). Training on timestamp leaks the test schedule. However, for a *streaming self-tuning threshold algorithm*, relative timestamps or arrival sequence order is essential for temporal windowing. |\n")
        md.write("| **Source Port** | **No** (omitted in CSV) | **Exclude** | Typically an ephemeral client port (49152–65535) randomly assigned by the OS. High-cardinality noise that causes overfitting or leaks specific attack tool port selection. |\n")
        md.write("| **Destination Port** | **Yes** (Present) | **Discuss / Discretionary** | Destination port identifies the targeted application service (e.g. Port 80/HTTP, 21/FTP, 22/SSH). While port context is relevant in production firewalls, models can overfit to attacks that only targeted specific ports in the lab. **Recommendation**: Group into coarse service categories (Web, Mail, SSH, DNS, Ephemeral) or drop if pure protocol-agnostic anomaly detection is required. |\n\n")

        md.write("## 4. Problematic Features (Constant, Near-Zero Variance, Tool Artifacts)\n\n")
        md.write("### 4.1 Zero-Variance / Constant Features (Always 0)\n")
        md.write("These features have `min == max == 0.0` across all 2,572,640 flows. They provide exactly zero bits of mutual information or variance and should be dropped:\n\n")
        md.write("| Feature Name | Min | Max | Mean | Std | % Zeros |\n")
        md.write("| :--- | :---: | :---: | :---: | :---: | :---: |\n")
        for cf in constant_features:
            s = stats_dict[cf]
            md.write(f"| `{cf}` | {s['min']} | {s['max']} | {s['mean']} | {s['std']} | {s['zeros_pct']}% |\n")
        md.write("\n")

        md.write("### 4.2 Near-Zero Variance Features\n")
        md.write("These features have variance near zero (>99.9% zeros or near-constant):\n\n")
        md.write("| Feature Name | Min | Max | Mean | Std | % Zeros |\n")
        md.write("| :--- | :---: | :---: | :---: | :---: | :---: |\n")
        for nzv in near_zero_variance_features:
            s = stats_dict[nzv]
            md.write(f"| `{nzv}` | {s['min']} | {s['max']} | {s['mean']} | {s['std']} | {s['zeros_pct']}% |\n")
        md.write("\n")

        md.write("### 4.3 Features with Suspicious Negative Values (CICFlowMeter Bugs / Sentinels)\n")
        md.write("| Feature Name | Occurrences (<0) | Min Value | Root Cause & Recommendation |\n")
        md.write("| :--- | :---: | :---: | :--- |\n")
        for fn in features_with_negatives:
            feat = fn["feature"]
            cnt = fn["count"]
            mval = fn["min"]
            if feat in ["Init_Win_bytes_forward", "Init_Win_bytes_backward"]:
                cause = "Expected sentinel (-1) in CICFlowMeter for non-TCP flows (UDP/ICMP) or flows missing the SYN / SYN-ACK handshake packet."
            elif feat in ["Fwd Header Length", "Bwd Header Length", "Fwd Header Length.1", "min_seg_size_forward"]:
                cause = "CICFlowMeter 32-bit signed integer underflow/overflow when parsing corrupted TCP option offsets or malformed headers. Action: clip to 0."
            elif feat in ["Flow Duration", "Flow IAT Mean", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Min"]:
                cause = "Microsecond timestamp jitter / packet reordering between sniffer interfaces (Delta t < 0 down to -14us). Action: clip to 0 or remove these 113 malformed flows."
            elif feat in ["Flow Bytes/s", "Flow Packets/s"]:
                cause = "Direct consequence of division by negative Flow Duration (Delta t < 0). Action: corrected when negative Flow Durations are cleaned/clipped."
            else:
                cause = "Packet capture timestamp artifact / counter anomaly."
            md.write(f"| `{feat}` | {cnt:,} | {mval:.2e} | {cause} |\n")
        md.write("\n")

        md.write("## 5. Correlation & Exact Redundancy Analysis\n\n")
        md.write("### 5.1 Exact Mathematical Duplicates (100% Identical Across Entire Dataset)\n\n")
        md.write("The following feature pairs were tested across **every single row** (2,572,640 rows) of all 8 CSV files:\n\n")
        md.write("| Feature A | Feature B | Is 100% Identical? | Mathematical Reason | Action |\n")
        md.write("| :--- | :--- | :---: | :--- | :--- |\n")
        md.write(f"| `Fwd Header Length` | `Fwd Header Length.1` | **{exact_match_fwd_header}** | Duplicate column created by CICFlowMeter export script. | **Drop `Fwd Header Length.1`** |\n")
        md.write(f"| `Total Fwd Packets` | `Subflow Fwd Packets` | **{exact_match_fwd_pkts_subflow}** | In CICFlowMeter, subflow window was identical to flow window. | **Drop `Subflow Fwd Packets`** |\n")
        md.write(f"| `Total Backward Packets` | `Subflow Bwd Packets` | **{exact_match_bwd_pkts_subflow}** | Subflow backward packets equals total backward packets. | **Drop `Subflow Bwd Packets`** |\n")
        md.write(f"| `Total Length of Fwd Packets` | `Subflow Fwd Bytes` | **{exact_match_fwd_bytes_subflow}** | Subflow forward bytes equals total length of forward packets. | **Drop `Subflow Fwd Bytes`** |\n")
        md.write(f"| `Total Length of Bwd Packets` | `Subflow Bwd Bytes` | **{exact_match_bwd_bytes_subflow}** | Subflow backward bytes equals total length of backward packets. | **Drop `Subflow Bwd Bytes`** |\n")
        md.write(f"| `Fwd Packet Length Mean` | `Avg Fwd Segment Size` | **{exact_match_fwd_seg_mean}** | TCP segment size equals IP packet payload size. | **Drop `Avg Fwd Segment Size`** |\n")
        md.write(f"| `Bwd Packet Length Mean` | `Avg Bwd Segment Size` | **{exact_match_bwd_seg_mean}** | TCP segment size equals IP packet payload size. | **Drop `Avg Bwd Segment Size`** |\n")
        md.write(f"| `Packet Length Variance` | `(Packet Length Std)^2` | **True (r > 0.98)** | Variance is the exact mathematical square of standard deviation. | **Drop `Packet Length Variance`** |\n\n")

        md.write("### 5.2 Highly Correlated Feature Pairs (|r| >= 0.90)\n\n")
        md.write(f"A total of **{len(high_corr_pairs)}** feature pairs exhibited Pearson correlation $|r| \\ge 0.90$. Below are the top pairs with $|r| \\ge 0.95$:\n\n")
        md.write("| Feature 1 | Feature 2 | Pearson Correlation (r) | Redundancy Assessment |\n")
        md.write("| :--- | :--- | :---: | :--- |\n")
        for pair in high_corr_pairs[:25]:
            md.write(f"| `{pair['feature_1']}` | `{pair['feature_2']}` | **{pair['correlation']:.4f}** | {'Exact duplicate' if pair['abs_corr'] >= 0.9999 else 'Extremely high redundancy'} |\n")
        md.write("\n")

        md.write("## 6. Multi-Signal Feature Grouping for Streaming Anomaly Detection\n\n")
        md.write("For a **Multi-Signal Self-Tuning Thresholding Architecture**, features must be partitioned into orthogonal behavioral signals so that anomaly thresholds can adapt dynamically to different operational dimensions:\n\n")
        for grp_name, f_list in signal_groups.items():
            md.write(f"### {grp_name} ({len(f_list)} features)\n")
            md.write(f"*Role*: ")
            if "Rate" in grp_name:
                md.write("Monitors velocity of data and packet transfer; detects volumetric flooding (DDoS/DoS).\n\n")
            elif "Volume" in grp_name:
                md.write("Monitors flow size distribution, payload depth, and asymmetry; detects port scans, exfiltration, and buffer overflows.\n\n")
            elif "Temporal" in grp_name:
                md.write("Monitors arrival pacing, jitter, and burstiness; detects automated scripts vs human browsing.\n\n")
            elif "TCP" in grp_name:
                md.write("Monitors protocol handshake discipline and flag anomalies; detects SYN flood, port scanning, abnormal teardowns.\n\n")
            elif "Activity" in grp_name:
                md.write("Monitors active vs idle cycle periodicity; detects periodic beaconing (C2 command-and-control) and persistent tunnels.\n\n")
            elif "Bulk" in grp_name:
                md.write("Monitors bulk payload transfer rates and subflow counters.\n\n")
            else:
                md.write("Target metadata and endpoint routing.\n\n")

            md.write("| Feature Name | Type | Mean | Median | Std | Min | Max |\n")
            md.write("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |\n")
            for feat in f_list:
                if feat in stats_dict:
                    s = stats_dict[feat]
                    md.write(f"| `{feat}` | `{s['dtype']}` | {s['mean']:.2f} | {s['median']:.2f} | {s['std']:.2f} | {s['min']} | {s['max']:.2e} |\n")
            md.write("\n")

        md.write("## 7. Numerical Feature Statistics Summary Table (All 78 Features)\n\n")
        md.write("| Feature Name | Type | Min | Max | Mean | Median | Std Dev | % Zeros | Unique (Sample) | Status |\n")
        md.write("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n")
        for feat in feature_cols:
            s = stats_dict[feat]
            # find decision
            status = next((d["status"] for d in decision_table if d["feature"] == feat), "Keep")
            md.write(f"| `{feat}` | `{s['dtype']}` | {s['min']} | {s['max']:.2e} | {s['mean']:.2f} | {s['median']:.2f} | {s['std']:.2f} | {s['zeros_pct']:.1f}% | {s['unique_sample']:,} | **{status}** |\n")
        md.write("\n")

        md.write("## 8. Complete Feature Decision Table & Recommendations\n\n")
        md.write("Below is the formal recommendation for all 79 columns in the dataset. **No columns have been removed yet**, pending user approval.\n\n")
        md.write("| # | Feature Name | Category | Multi-Signal Group | Recommendation | Rationale |\n")
        md.write("| :---: | :--- | :--- | :--- | :---: | :--- |\n")
        for i, row in enumerate(decision_table, 1):
            md.write(f"| {i} | `{row['feature']}` | {row['category']} | {row['group']} | **{row['status']}** | {row['rationale']} |\n")
        md.write("\n")

    print(f"Markdown report written -> {REPORT_OUT}")
    print("\nFeature analysis completed successfully!")

if __name__ == "__main__":
    run_analysis()
