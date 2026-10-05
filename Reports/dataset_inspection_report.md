# Step 1 — Dataset Inspection Report: CSE-CIC-IDS2018

> **Read-only inspection. No files were modified, renamed, deleted, or overwritten.**

---

## Dataset Location

```
c:\Work\Big data\MachineLearningCVE\
```

---

## Column Schema (shared across all 8 files)

All 8 files share **identical column names and order** (79 columns). Column names had leading/trailing whitespace stripped before inspection.

| # | Column Name | Dtype | # | Column Name | Dtype |
|---|---|---|---|---|---|
| 1 | Destination Port | int64 | 41 | Packet Length Mean | float64 |
| 2 | Flow Duration | int64 | 42 | Packet Length Std | float64 |
| 3 | Total Fwd Packets | int64 | 43 | Packet Length Variance | float64 |
| 4 | Total Backward Packets | int64 | 44 | FIN Flag Count | int64 |
| 5 | Total Length of Fwd Packets | int64 | 45 | SYN Flag Count | int64 |
| 6 | Total Length of Bwd Packets | int64 | 46 | RST Flag Count | int64 |
| 7 | Fwd Packet Length Max | int64 | 47 | PSH Flag Count | int64 |
| 8 | Fwd Packet Length Min | int64 | 48 | ACK Flag Count | int64 |
| 9 | Fwd Packet Length Mean | float64 | 49 | URG Flag Count | int64 |
| 10 | Fwd Packet Length Std | float64 | 50 | CWE Flag Count | int64 |
| 11 | Bwd Packet Length Max | int64 | 51 | ECE Flag Count | int64 |
| 12 | Bwd Packet Length Min | int64 | 52 | Down/Up Ratio | int64 |
| 13 | Bwd Packet Length Mean | float64 | 53 | Average Packet Size | float64 |
| 14 | Bwd Packet Length Std | float64 | 54 | Avg Fwd Segment Size | float64 |
| 15 | **Flow Bytes/s** | **float64** | 55 | Avg Bwd Segment Size | float64 |
| 16 | **Flow Packets/s** | **float64** | 56 | **Fwd Header Length.1** | int64 |
| 17 | Flow IAT Mean | float64 | 57 | Fwd Avg Bytes/Bulk | int64 |
| 18 | Flow IAT Std | float64 | 58 | Fwd Avg Packets/Bulk | int64 |
| 19 | Flow IAT Max | int64 | 59 | Fwd Avg Bulk Rate | int64 |
| 20 | Flow IAT Min | int64 | 60 | Bwd Avg Bytes/Bulk | int64 |
| 21 | Fwd IAT Total | int64 | 61 | Bwd Avg Packets/Bulk | int64 |
| 22 | Fwd IAT Mean | float64 | 62 | Bwd Avg Bulk Rate | int64 |
| 23 | Fwd IAT Std | float64 | 63 | Subflow Fwd Packets | int64 |
| 24 | Fwd IAT Max | int64 | 64 | Subflow Fwd Bytes | int64 |
| 25 | Fwd IAT Min | int64 | 65 | Subflow Bwd Packets | int64 |
| 26 | Bwd IAT Total | int64 | 66 | Subflow Bwd Bytes | int64 |
| 27 | Bwd IAT Mean | float64 | 67 | Init_Win_bytes_forward | int64 |
| 28 | Bwd IAT Std | float64 | 68 | Init_Win_bytes_backward | int64 |
| 29 | Bwd IAT Max | int64 | 69 | act_data_pkt_fwd | int64 |
| 30 | Bwd IAT Min | int64 | 70 | min_seg_size_forward | int64 |
| 31 | Fwd PSH Flags | int64 | 71 | Active Mean | float64 |
| 32 | Bwd PSH Flags | int64 | 72 | Active Std | float64 |
| 33 | Fwd URG Flags | int64 | 73 | Active Max | int64 |
| 34 | Bwd URG Flags | int64 | 74 | Active Min | int64 |
| 35 | Fwd Header Length | int64 | 75 | Idle Mean | float64 |
| 36 | Bwd Header Length | int64 | 76 | Idle Std | float64 |
| 37 | Fwd Packets/s | float64 | 77 | Idle Max | int64 |
| 38 | Bwd Packets/s | float64 | 78 | Idle Min | int64 |
| 39 | Min Packet Length | int64 | 79 | **Label** | object (str) |
| 40 | Max Packet Length | int64 | | | |

> **Notes:**
> - **Fwd Header Length.1** (col 56) is a duplicate of col 35 — same data, artifact of the CICFlowMeter tool.
> - **Flow Bytes/s** and **Flow Packets/s** are the ONLY columns with NaN or +Inf values.
> - **No timestamp column exists** in any file. Files are named by day/session.
> - **Label** is `object` type (stored as string), not encoded.

---

## Per-File Inspection

---

### File 1 — `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`

| Property | Value |
|---|---|
| **File Size** | 73.55 MB |
| **Rows** | 225,745 |
| **Columns** | 79 |

**Missing Values (NaN):**
| Column | NaN Count |
|---|---|
| Flow Bytes/s | 4 |
| All other 78 columns | 0 |
| **Total** | **4** |

**Infinity Values:**
| Column | +Inf | -Inf |
|---|---|---|
| Flow Bytes/s | 30 | 0 |
| Flow Packets/s | 34 | 0 |
| **Total** | **64** | **0** |

**Duplicate Rows:** 2,633

**Label Distribution:**
| Label | Count | % |
|---|---|---|
| DDoS | 128,027 | 56.7% |
| BENIGN | 97,718 | 43.3% |

**Timestamp Column:** ❌ None found.

**First 5 Rows (selected columns):**

| Dest Port | Flow Duration | Fwd Pkts | Bwd Pkts | Flow Bytes/s | Flow Pkts/s | Label |
|---|---|---|---|---|---|---|
| 54865 | 3 | 2 | 0 | 4,000,000.0 | 666,666.67 | BENIGN |
| 55054 | 109 | 1 | 1 | 110,091.74 | 18,348.62 | BENIGN |
| 55055 | 52 | 1 | 1 | 230,769.23 | 38,461.54 | BENIGN |
| 46236 | 34 | 1 | 1 | 352,941.18 | 58,823.53 | BENIGN |
| 54863 | 3 | 2 | 0 | 4,000,000.0 | 666,666.67 | BENIGN |

---

### File 2 — `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`

| Property | Value |
|---|---|
| **File Size** | 73.34 MB |
| **Rows** | 286,467 |
| **Columns** | 79 |

**Missing Values (NaN):**
| Column | NaN Count |
|---|---|
| Flow Bytes/s | 15 |
| All other 78 columns | 0 |
| **Total** | **15** |

**Infinity Values:**
| Column | +Inf | -Inf |
|---|---|---|
| Flow Bytes/s | 356 | 0 |
| Flow Packets/s | 371 | 0 |
| **Total** | **727** | **0** |

**Duplicate Rows:** 72,353

**Label Distribution:**
| Label | Count | % |
|---|---|---|
| PortScan | 158,930 | 55.5% |
| BENIGN | 127,537 | 44.5% |

**Timestamp Column:** ❌ None found.

**First 5 Rows (selected columns):**

| Dest Port | Flow Duration | Fwd Pkts | Bwd Pkts | Flow Bytes/s | Flow Pkts/s | Label |
|---|---|---|---|---|---|---|
| 22 | 1,266,342 | 41 | 44 | 7,595.10 | 67.12 | BENIGN |
| 22 | 1,319,353 | 41 | 44 | 7,289.94 | 64.43 | BENIGN |
| 22 | 160 | 1 | 1 | 0.0 | 12,500.0 | BENIGN |
| 22 | 1,303,488 | 41 | 42 | 7,182.27 | 63.68 | BENIGN |
| 35396 | 77 | 1 | 2 | 0.0 | 38,961.04 | BENIGN |

---

### File 3 — `Friday-WorkingHours-Morning.pcap_ISCX.csv`

| Property | Value |
|---|---|
| **File Size** | 55.62 MB |
| **Rows** | 191,033 |
| **Columns** | 79 |

**Missing Values (NaN):**
| Column | NaN Count |
|---|---|
| Flow Bytes/s | 28 |
| All other 78 columns | 0 |
| **Total** | **28** |

**Infinity Values:**
| Column | +Inf | -Inf |
|---|---|---|
| Flow Bytes/s | 94 | 0 |
| Flow Packets/s | 122 | 0 |
| **Total** | **216** | **0** |

**Duplicate Rows:** 6,888

**Label Distribution:**
| Label | Count | % |
|---|---|---|
| BENIGN | 189,067 | 99.0% |
| Bot | 1,966 | 1.0% |

**Timestamp Column:** ❌ None found.

**First 5 Rows (selected columns):**

| Dest Port | Flow Duration | Fwd Pkts | Bwd Pkts | Flow Bytes/s | Flow Pkts/s | Label |
|---|---|---|---|---|---|---|
| 3268 | 112,740,690 | 32 | 16 | 67.41 | 0.43 | BENIGN |
| 389 | 112,740,560 | 32 | 16 | 102.04 | 0.43 | BENIGN |
| 0 | 113,757,377 | 545 | 0 | 0.0 | 4.79 | BENIGN |
| 5355 | 100,126 | 22 | 0 | 6,152.25 | 219.72 | BENIGN |
| 0 | 54,760 | 4 | 0 | 0.0 | 73.05 | BENIGN |

---

### File 4 — `Monday-WorkingHours.pcap_ISCX.csv`

| Property | Value |
|---|---|
| **File Size** | 168.73 MB |
| **Rows** | 529,918 |
| **Columns** | 79 |

**Missing Values (NaN):**
| Column | NaN Count |
|---|---|
| Flow Bytes/s | 64 |
| All other 78 columns | 0 |
| **Total** | **64** |

**Infinity Values:**
| Column | +Inf | -Inf |
|---|---|---|
| Flow Bytes/s | 373 | 0 |
| Flow Packets/s | 437 | 0 |
| **Total** | **810** | **0** |

**Duplicate Rows:** 26,935

**Label Distribution:**
| Label | Count | % |
|---|---|---|
| BENIGN | 529,918 | 100.0% |

> Monday is a **baseline BENIGN-only** capture day.

**Timestamp Column:** ❌ None found.

**First 5 Rows (selected columns):**

| Dest Port | Flow Duration | Fwd Pkts | Bwd Pkts | Flow Bytes/s | Flow Pkts/s | Label |
|---|---|---|---|---|---|---|
| 49188 | 4 | 2 | 0 | 3,000,000.0 | 500,000.0 | BENIGN |
| 49188 | 1 | 2 | 0 | 12,000,000.0 | 2,000,000.0 | BENIGN |
| 49188 | 2 | 2 | 0 | 6,000,000.0 | 1,000,000.0 | BENIGN |
| 135 | 35,889 | 40 | 0 | 8,917.34 | 1,114.67 | BENIGN |
| 49192 | 4 | 2 | 0 | 3,000,000.0 | 500,000.0 | BENIGN |

---

### File 5 — `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`

| Property | Value |
|---|---|
| **File Size** | 79.25 MB |
| **Rows** | 288,602 |
| **Columns** | 79 |

**Missing Values (NaN):**
| Column | NaN Count |
|---|---|
| Flow Bytes/s | 18 |
| All other 78 columns | 0 |
| **Total** | **18** |

**Infinity Values:**
| Column | +Inf | -Inf |
|---|---|---|
| Flow Bytes/s | 178 | 0 |
| Flow Packets/s | 218 | 0 |
| **Total** | **396** | **0** |

**Duplicate Rows:** 35,630

**Label Distribution:**
| Label | Count | % |
|---|---|---|
| BENIGN | 288,566 | 99.99% |
| Infiltration | 36 | 0.01% |

**Timestamp Column:** ❌ None found.

---

### File 6 — `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`

| Property | Value |
|---|---|
| **File Size** | 49.61 MB |
| **Rows** | 170,366 |
| **Columns** | 79 |

**Missing Values (NaN):**
| Column | NaN Count |
|---|---|
| Flow Bytes/s | 20 |
| All other 78 columns | 0 |
| **Total** | **20** |

**Infinity Values:**
| Column | +Inf | -Inf |
|---|---|---|
| Flow Bytes/s | 109 | 0 |
| Flow Packets/s | 141 | 0 |
| **Total** | **250** | **0** |

**Duplicate Rows:** 6,066

**Label Distribution:**
| Label | Count | % |
|---|---|---|
| BENIGN | 168,186 | 98.7% |
| Web Attack – Brute Force | 1,507 | 0.88% |
| Web Attack – XSS | 652 | 0.38% |
| Web Attack – Sql Injection | 21 | 0.01% |

> ⚠️ Label strings contain Unicode replacement characters (encoding artifact from source CSV). Raw labels: `"Web Attack \ufffd Brute Force"`, etc.

**Timestamp Column:** ❌ None found.

---

### File 7 — `Tuesday-WorkingHours.pcap_ISCX.csv`

| Property | Value |
|---|---|
| **File Size** | 128.82 MB |
| **Rows** | 445,909 |
| **Columns** | 79 |

**Missing Values (NaN):**
| Column | NaN Count |
|---|---|
| Flow Bytes/s | 201 |
| All other 78 columns | 0 |
| **Total** | **201** |

**Infinity Values:**
| Column | +Inf | -Inf |
|---|---|---|
| Flow Bytes/s | 142 | 0 |
| Flow Packets/s | 185 | 0 |
| **Total** | **327** | **0** |

**Duplicate Rows:** 24,065

**Label Distribution:**
| Label | Count | % |
|---|---|---|
| BENIGN | 432,074 | 96.9% |
| FTP-Patator | 7,938 | 1.78% |
| SSH-Patator | 5,897 | 1.32% |

**Timestamp Column:** ❌ None found.

---

### File 8 — `Wednesday-workingHours.pcap_ISCX.csv`

| Property | Value |
|---|---|
| **File Size** | 214.74 MB |
| **Rows** | 692,703 |
| **Columns** | 79 |

**Missing Values (NaN):**
| Column | NaN Count |
|---|---|
| Flow Bytes/s | 1,008 |
| All other 78 columns | 0 |
| **Total** | **1,008** |

**Infinity Values:**
| Column | +Inf | -Inf |
|---|---|---|
| Flow Bytes/s | 692 | 0 |
| Flow Packets/s | 894 | 0 |
| **Total** | **1,586** | **0** |

**Duplicate Rows:** 81,909

**Label Distribution:**
| Label | Count | % |
|---|---|---|
| BENIGN | 440,031 | 63.5% |
| DoS Hulk | 231,073 | 33.4% |
| DoS GoldenEye | 10,293 | 1.49% |
| DoS slowloris | 5,796 | 0.84% |
| DoS Slowhttptest | 5,499 | 0.79% |
| Heartbleed | 11 | <0.01% |

**Timestamp Column:** ❌ None found.

---

## Cross-File Summary Table

| File | Size (MB) | Rows | NaN | +Inf | Dups | Attack Labels |
|---|---|---|---|---|---|---|
| Fri-DDos | 73.55 | 225,745 | 4 | 64 | 2,633 | DDoS |
| Fri-PortScan | 73.34 | 286,467 | 15 | 727 | 72,353 | PortScan |
| Fri-Morning | 55.62 | 191,033 | 28 | 216 | 6,888 | Bot |
| Monday | 168.73 | 529,918 | 64 | 810 | 26,935 | *(BENIGN only)* |
| Thu-Infiltration | 79.25 | 288,602 | 18 | 396 | 35,630 | Infiltration |
| Thu-WebAttacks | 49.61 | 170,366 | 20 | 250 | 6,066 | Web Attack ×3 |
| Tuesday | 128.82 | 445,909 | 201 | 327 | 24,065 | FTP-Patator, SSH-Patator |
| Wednesday | 214.74 | 692,703 | 1,008 | 1,586 | 81,909 | DoS×4, Heartbleed |
| **TOTAL** | **843.66** | **2,830,743** | **1,358** | **4,376** | **256,479** | **15 label types** |

---

## Timestamp Column Analysis

**No dedicated timestamp column exists in any file.**

- The CICFlowMeter tool exports pre-computed flow statistics. Timestamps are embedded in flow fields (like `Flow Duration`), not as an explicit date-time column.
- The only "time-like" information is `Flow Duration` (in microseconds, `int64`) — this is the *duration* of a flow, not an absolute wall-clock timestamp.
- **Chronological ordering:** Cannot be determined per file since no absolute timestamp column exists. Ordering across files must be inferred from file names (Mon → Tue → Wed → Thu morning → Thu afternoon → Fri morning → Fri afternoon DDos → Fri afternoon PortScan).

---

## Overall Label Distribution (All 8 Files Combined)

| Label | Count | % of Total |
|---|---|---|
| **BENIGN** | 2,273,097 | **80.30%** |
| DoS Hulk | 231,073 | 8.16% |
| PortScan | 158,930 | 5.61% |
| DDoS | 128,027 | 4.52% |
| DoS GoldenEye | 10,293 | 0.36% |
| FTP-Patator | 7,938 | 0.28% |
| SSH-Patator | 5,897 | 0.21% |
| DoS slowloris | 5,796 | 0.20% |
| DoS Slowhttptest | 5,499 | 0.19% |
| Web Attack – Brute Force | 1,507 | 0.05% |
| Web Attack – XSS | 652 | 0.02% |
| Bot | 1,966 | 0.07% |
| Infiltration | 36 | <0.01% |
| Web Attack – Sql Injection | 21 | <0.01% |
| Heartbleed | 11 | <0.01% |
| **Total Attacks** | **557,646** | **19.70%** |

> ⚠️ **Severe class imbalance.** BENIGN is 80.3% of all traffic. Minority classes (Infiltration=36, Heartbleed=11, SQL Injection=21) are extremely rare.

---

## Notable Observations

1. **`Fwd Header Length.1`** (col 56) is a **verbatim duplicate of `Fwd Header Length`** (col 35) — a known CICFlowMeter bug.
2. **Only `Flow Bytes/s`** has NaN values — these occur when `Flow Duration = 0` (division by zero in the tool).
3. **Only `Flow Bytes/s` and `Flow Packets/s`** contain `+Inf` — same root cause (0-duration flows).
4. **No `-Inf` values** anywhere in the dataset.
5. **`Init_Win_bytes_backward`** frequently shows `-1` (meaning no backward packets / no window size recorded) — these are valid sentinel values, not errors.
6. **Web Attack labels** contain a **Unicode replacement character (`\ufffd`)** — the original CSV was encoded differently from the reader's expectation (likely UTF-8 vs Windows-1252 encoding mismatch). The actual label separator character is a special dash (e.g., em-dash or a non-ASCII character).
7. **Duplicate rows** are substantial in some files (PortScan: 72,353 = 25.2%, Wednesday: 81,909 = 11.8%). These may be legitimately repeated flows or data entry artifacts.

---

## Dataset Inspection Summary

| Property | Value |
|---|---|
| **Total CSV Files** | 8 |
| **Total Rows** | 2,830,743 |
| **Total Columns** | 79 (identical across all files) |
| **Column Schema Consistent?** | ✅ Yes — all 8 files share identical columns |
| **Missing Values (NaN)** | 1,358 total — **exclusively in `Flow Bytes/s`** column only. Caused by 0-duration flows (division by zero). Very small proportion (<0.05%). |
| **+Infinity Values** | 4,376 total — **in `Flow Bytes/s` and `Flow Packets/s`** only. Same root cause. |
| **-Infinity Values** | 0 — None anywhere. |
| **Duplicate Rows** | 256,479 total (9.1% of all rows). Heaviest in PortScan (25.2%) and Wednesday (11.8%). |
| **Label Column** | `Label` (object/string type, col 79). **15 unique label values.** Severe class imbalance: 80.3% BENIGN vs 19.7% attack traffic. |
| **Timestamp Column** | ❌ **No timestamp column exists.** Chronological ordering must rely on file names only. |
| **Known Data Issues** | (1) Duplicate `Fwd Header Length.1` column; (2) Web Attack labels have Unicode encoding artifact; (3) `Init_Win_bytes_backward = -1` sentinel values; (4) Extreme minority classes (11–36 samples). |
