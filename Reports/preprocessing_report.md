# Preprocessing and Feature Engineering Report

**Project Title**: Multi-Signal Self-Tuning Thresholds for Streaming Anomaly Detection  
**Dataset**: CSE-CIC-IDS2018 Network Traffic Dataset  
**Target Stage**: Preprocessing & Feature Engineering *(Completed)*  
**Presentation Audience**: Academic Evaluation, Viva, and Project Team  

---

## 1. Overview

Before machine learning models can detect cyberattacks in network traffic, the raw data must be cleaned, checked, and properly structured. Raw network traffic logs contain measurement glitches, duplicate records, missing entries, and redundant features that can mislead models.

This report explains the complete preprocessing and feature-engineering pipeline that turned raw network packet captures into a clean, well-balanced dataset ready for distributed processing with Spark and anomaly detection with Isolation Forest.

> **Key Rule**: Preprocessing is 100% complete. No machine learning models, anomaly scores, or thresholding algorithms have been trained or run yet.

---

## 2. Dataset Before Preprocessing

The raw dataset comes from the **CSE-CIC-IDS2018** benchmark, which contains realistic background traffic mixed with several common cyberattacks (such as DDoS, Port Scans, Web Attacks, and Infiltration).

### What is a Network Flow?
> **Network Flow**: A flow represents two-way communication between two network devices (such as a client laptop and a server) during a specific session.

### Initial Dataset Summary

| Property | Value | Explanation |
| :--- | :---: | :--- |
| **Number of CSV files** | **8 files** | Each file corresponds to network activity recorded on different days. |
| **Total raw rows (flows)** | **2,830,743** | Total connection sessions captured. |
| **Original numerical features** | **78** | Measurable traffic properties per flow (bytes, packet counts, timings). |
| **Target label** | **`Label`** | Ground truth showing whether the flow was `BENIGN` or an attack. |
| **Initial data format** | **Raw CSV** | Comma-separated text files. |

---

## 3. Step 1 — Data Cleaning

Raw network measurement tools can fail or produce incomplete flow records. We inspected every row to find broken or impossible records.

| Problem Found | What We Did | Why We Did It |
| :--- | :--- | :--- |
| **Zero Duration Flows (`Flow Duration == 0`)** | Removed 2,867 flows | A flow cannot start and end in zero time while transferring data. These broken flows were the direct root cause of division-by-zero errors that created `NaN` and `+Infinity` values. |
| **Missing Values (`NaN`)** | Handled by removing the zero-duration flows | All missing values occurred only within these broken flows. Once they were removed, exactly 0 missing values remained. |
| **Infinite Values (`+Infinity`, `-Infinity`)** | Handled by removing the zero-duration flows | Rates calculated by dividing by zero duration produced infinite numbers. Removing these flows eliminated all infinite values without needing artificial guessing. |
| **Corrupted Text Encoding** | Replaced `\ufffd` with an en-dash `–` in attack labels | A software text-encoding bug in the Web Attack file had replaced dashes with unknown symbols (`Web Attack  Brute Force`). |

---

## 4. Step 2 — Removing Duplicate Data

When capturing gigabytes of high-speed network traffic across multiple monitoring points, the exact same packet or flow is often recorded more than once.

| Step | What We Found | What We Did | Why We Did It |
| :--- | :--- | :--- | :--- |
| **Exact Duplicate Rows** | 255,236 duplicate rows across all 8 files | Kept only the first occurrence and dropped exact copies | Duplicate records artificially inflate model performance metrics and cause the model to count the exact same session multiple times. |
| **Row Order** | Flows were originally arranged chronologically | Strictly preserved row order (no random shuffling) | Crucial for streaming detection, where arriving flows must keep their natural time sequence. |

### Summary of Cleaning Numbers

| Cleaning Operation | Flow Count | Percentage of Original |
| :--- | ---: | :---: |
| **Original Raw Rows** | **2,830,743** | 100.00% |
| Invalid zero-duration / NaN / Infinite flows removed | -2,867 | 0.10% |
| Exact duplicate rows removed | -255,236 | 9.02% |
| **Cleaned Rows Remaining** | **2,572,640** | **90.88%** |

> Exactly **2,572,640 clean flows** remained, with zero missing values, zero infinite values, and zero duplicate records.

---

## 5. Step 3 — Feature Analysis

Before deleting or modifying any column, we analyzed every single feature across the entire cleaned dataset.

### What is a Feature?
> **Feature**: A measurable property of a network flow, such as total packet count, byte size, duration, or TCP protocol flag count.

### What We Investigated

| Area | What We Looked For | Why It Matters |
| :--- | :--- | :--- |
| **Constant Features** | Features that never change across all 2.57M flows | Columns with only one constant value provide zero clues to detect attacks. |
| **Duplicate Features** | Pairs of columns measuring the exact same quantity | Keeping identical columns doubles storage without adding any new information. |
| **Highly Related Features** | Pairs of features with correlation above 0.90 | Helps identify which features are repeating the same facts in different forms. |
| **Invalid Negative Values** | Features with numbers below zero (such as negative duration) | Physical metrics like time, packet count, or byte size cannot be negative. |
| **Sentinel Values** | Numbers like `-1` used as placeholders | Must be handled carefully so the model does not treat a placeholder as a real negative quantity. |

---

## 6. Step 4 — Removing Unnecessary Features

We permanently removed **16 features** that were confirmed to be either completely constant or exact duplicates of other columns.

### A. Constant Features (8 features removed)
> **Constant feature**: A feature that has the exact same value for every single flow.

These features were all `0.0` across all 2,572,640 rows, giving zero information:
1. `Bwd PSH Flags`
2. `Bwd URG Flags`
3. `Fwd Avg Bytes/Bulk`
4. `Fwd Avg Packets/Bulk`
5. `Fwd Avg Bulk Rate`
6. `Bwd Avg Bytes/Bulk`
7. `Bwd Avg Packets/Bulk`
8. `Bwd Avg Bulk Rate`

### B. Duplicate / Redundant Features (8 features removed)
> **Duplicate feature**: A feature that gives essentially the exact same information as another feature already in the table.

| Removed Feature | Kept Alternative | Why It Was Removed |
| :--- | :--- | :--- |
| `Fwd Header Length.1` | `Fwd Header Length` | Exact 100% duplicate column created by a software export bug. |
| `Subflow Fwd Packets` | `Total Fwd Packets` | Exact 100% identical copy; both counted the same packets. |
| `Subflow Bwd Packets` | `Total Backward Packets` | Exact 100% identical copy. |
| `Subflow Fwd Bytes` | `Total Length of Fwd Packets` | 100% correlation ($r = 1.0000$); measured the same byte count. |
| `Subflow Bwd Bytes` | `Total Length of Bwd Packets` | 100% correlation ($r = 1.0000$); measured the same byte count. |
| `Avg Fwd Segment Size` | `Fwd Packet Length Mean` | Exact 100% identical copy; packet size equals segment size in IP traffic. |
| `Avg Bwd Segment Size` | `Bwd Packet Length Mean` | Exact 100% identical copy. |
| `Packet Length Variance` | `Packet Length Std` | Exact mathematical square of standard deviation; redundant information. |

### Rare Protocol Flags Kept
We deliberately **kept** 4 rare flags (`Fwd URG Flags`, `CWE Flag Count`, `ECE Flag Count`, `RST Flag Count`). Even though they appear rarely, rare flags are often signatures of stealthy port scans or attack attempts.

---

## 7. Step 5 — Fixing Invalid Values

Due to microsecond timer drift and software overflow bugs in the original capture software (CICFlowMeter), a small number of rows had negative numbers in fields that should never be negative. We corrected these using network domain knowledge rather than deleting the rows.

| Feature | Problem Found | Correction Applied | Why We Did It |
| :--- | :--- | :--- | :--- |
| **`Flow Duration`** | 113 flows had negative duration (down to $-13\,\mu\text{s}$) | Corrected to its absolute physical duration ($\ge 1\,\mu\text{s}$) | In 2-packet connections, slight clock differences between two sniffer cards recorded the reply packet a few microseconds before the first packet. The true duration was near-instantaneous. |
| **`Flow Bytes/s`** | 84 flows had negative rates (down to $-2.61 \times 10^8$) | Recalculated using the corrected positive duration | Negative transfer rates were mathematical side-effects of dividing total bytes by negative duration. Correcting duration restored positive rates. |
| **`Flow Packets/s`** | 113 flows had negative packet rates | Recalculated using the corrected positive duration | Same as above. Packet transfer speed can never be negative. |
| **IAT Timing Features** | Small negative times (down to $-14\,\mu\text{s}$) | Clipped to minimum `0.0` | Packet inter-arrival time (time between two packets) cannot physically be less than zero. |
| **`Fwd Header Length`** | 35 flows had huge negative numbers (down to $-3.22 \times 10^{10}$) | Replaced with $\text{Total Fwd Packets} \times 20\text{ bytes}$ | A 32-bit signed integer underflow bug occurred in Java when parsing damaged packet headers. Restored the standard minimum 20-byte TCP header. |
| **`Bwd Header Length`** | 22 flows had huge negative numbers (down to $-1.07 \times 10^9$) | Replaced with $\text{Total Backward Packets} \times 20\text{ bytes}$ | Same 32-bit integer underflow bug on backward packets. Restored the standard minimum 20-byte TCP header. |
| **`min_seg_size_forward`** | 35 flows had huge negative numbers (down to $-5.37 \times 10^8$) | Replaced with standard minimum `20` | Restored the standard minimum TCP segment size (20 bytes). |

---

## 8. Step 6 — Handling Special / Sentinel Values

### What is a Sentinel Value?
> **Sentinel Value**: A special placeholder number (like `-1`) used by logging software to mean *"this information is missing or not applicable."*

In the two TCP window size columns (`Init_Win_bytes_forward` and `Init_Win_bytes_backward`), the number `-1` appeared in hundreds of thousands of flows (37% and 49% of rows). This happened because non-TCP flows (such as UDP or ICMP) do not have TCP windows, or the initial connection handshake was not captured.

If left as `-1`, machine learning models would mistakenly treat `-1` as a real negative window capacity. If deleted, we would lose over a million valid flows.

### Our Solution
We split each column into two clear, clean pieces of information:

| Original Column | New Column 1: Presence Indicator | New Column 2: Clean Numerical Size |
| :--- | :--- | :--- |
| `Init_Win_bytes_forward` | `has_init_win_forward`<br>*(1 = TCP window present, 0 = not applicable)* | `init_win_bytes_forward_clean`<br>*(Valid window bytes, with placeholder set to 0)* |
| `Init_Win_bytes_backward` | `has_init_win_backward`<br>*(1 = Response window present, 0 = not applicable)* | `init_win_bytes_backward_clean`<br>*(Valid window bytes, with placeholder set to 0)* |

---

## 9. Step 7 — Feature Transformation

### Why Did We Transform Features?
> **Skewed Distribution**: When most flows have small numbers (like 2 packets or 100 bytes), but a few flows have huge numbers (like 200,000 packets or 600,000,000 bytes).

If left untransformed, the massive values dominate machine learning calculations and prevent the model from learning subtle patterns in everyday traffic.

### What is `log1p`?
> **`log1p(x)`**: A simple mathematical formula, $\log(1 + x)$, that compresses massive numbers into a smooth, manageable scale while keeping zero as zero.

```
Example of log1p compression:
     0 bytes  ──>  0.0
   100 bytes  ──>  4.6
 1,000 bytes  ──>  6.9
 1,000,000 bytes  ──> 13.8
```

### Which Features Were Transformed?
- **Transformed with `log1p`**: Continuous quantities with huge ranges (e.g., `Flow Bytes/s`, `Flow Duration`, `Total Fwd Packets`, `Fwd Packet Length Mean`, all IAT timings, and window sizes).
- **Kept as Normal Linear Numbers**: Binary flags (like `SYN Flag Count`, `FIN Flag Count`), presence indicators (`has_init_win_forward`), and small bounded ratios (`Down/Up Ratio`).

---

## 10. Step 8 — Creating Useful Features (Destination Port Grouping)

In network security, looking only at the raw destination port number (such as `80` or `22`) can cause the model to memorize the test lab setup rather than learning real attack behavior.

To solve this, we kept the raw `Destination Port` for reference and created a new, descriptive service category called `destination_port_group`.

| Service Category | Port Numbers Included | Why This Grouping Was Chosen |
| :--- | :--- | :--- |
| **Web** | 80, 443, 8080, 8443, 8000, 8888, 5000 | Standard website traffic (HTTP, HTTPS, and web proxies). |
| **SSH** | 22 | Secure remote command-line login. |
| **FTP** | 20, 21, 989, 990 | File transfer protocol control and data channels. |
| **DNS** | 53, 5353, 5355 | Domain name lookup services. |
| **Mail** | 25, 110, 143, 465, 587, 993, 995 | Email sending and receiving protocols. |
| **Ephemeral / High Port** | 49152 to 65535 | Temporary ports automatically assigned by client computers. |
| **Other / Common** | All other registered ports | Standard enterprise services (like databases, SMB file sharing, LDAP). |

---

## 11. Step 9 — Grouping Features into Signals

A central innovation of our project is **Multi-Signal Self-Tuning Thresholds**. Rather than relying on a single overall anomaly score, we organize the **63 modeling features** into **5 behavioral signal groups**:

| Signal Group | Feature Count | What It Measures | What Kind of Attacks It Helps Detect |
| :--- | :---: | :--- | :--- |
| **1. Volume & Size** | 19 features | Total bytes transferred, packet lengths, and flow sizes | Data exfiltration, buffer overflow attempts, and port scanning probes. |
| **2. Rate & Velocity** | 4 features | Speed of data and packet transfer per second | Volumetric flooding attacks (such as DDoS and high-rate DoS). |
| **3. Temporal / IAT** | 15 features | Duration of connection and time gaps between packets | Automated attack scripts, rapid port scanners, and timing jitter. |
| **4. TCP Protocol & Flags** | 17 features | Protocol handshake behavior, flags, and header overhead | SYN floods, stealth port scans, and abnormal connection resets. |
| **5. Activity & Silence** | 8 features | Active transmission bursts vs. dormant silence periods | Command-and-control (C2) beaconing, Slowloris, and hidden tunnels. |

> **Why Group Features?**  
> Grouping features allows our system to look for anomalies across distinct operational dimensions simultaneously. An attack that tries to hide its packet volume will still stand out because of its abnormal timing or protocol flag behavior.

---

## 12. Step 10 — Creating the Final Dataset

The final processed data was exported into **Apache Parquet format with Snappy compression**, making it ready for distributed processing on Hadoop and Spark.

### Summary of Final Schema Columns

| Category | Column Count | Column Names |
| :--- | :---: | :--- |
| **Modeling Features** | **63** | 19 Volume + 4 Rate + 15 Temporal + 17 Protocol + 8 Activity features |
| **Context Columns** | **2** | `Destination Port` (raw number) and `destination_port_group` (service name) |
| **Evaluation Labels** | **2** | `Label` (attack name string) and `is_anomaly` (0 for Benign, 1 for Attack) |
| **Total Parquet Columns** | **67** | All 67 columns verified clean and non-null |

---

## 13. Before vs After Summary

| Metric | Raw Dataset (Before) | Processed Dataset (After) | Change / Impact |
| :--- | :---: | :---: | :--- |
| **Total Rows (Flows)** | 2,830,743 | **2,572,640** | 258,103 bad/duplicate rows cleanly removed (90.9% kept) |
| **Numerical Features** | 78 raw features | **63 clean modeling features** | Removed 16 useless/duplicate columns; added 5 clear features |
| **Missing Values (NaN)** | Present (in broken flows) | **0** | Clean, complete dataset with zero missing data |
| **Infinite Values ($\pm\infty$)** | Present (division by zero) | **0** | Eliminated completely without artificial imputation |
| **Duplicate Rows** | 255,236 duplicates | **0** | No repeated or over-counted flows |
| **Physically Impossible Negatives** | Present (in 113+ flows) | **0** | Restored to valid physical and protocol values |
| **Extreme Outlier Skew** | Extreme (up to $10^9$) | **Smoothed with `log1p`** | Models will not be blinded by a few massive flows |
| **Storage Format** | Multiple raw CSV files | **8 Snappy Parquet files** | Compressed, optimized, and ready for Spark / HDFS |

---

## 14. Final Data Quality Check

Every file in the final dataset passed strict automated quality verification:

| Quality Verification Check | Target Standard | Observed Result | Status |
| :--- | :---: | :---: | :---: |
| **Total Flow Count** | 2,572,640 flows | 2,572,640 flows | **PASS** |
| **Missing Values (`NaN`)** | Exactly 0 | 0 | **PASS** |
| **Infinite Values (`Inf`)** | Exactly 0 | 0 | **PASS** |
| **Impossible Negative Values** | Exactly 0 | 0 | **PASS** |
| **Duplicate Records** | Exactly 0 | 0 | **PASS** |
| **Row Order Integrity** | Chronological order | Strictly preserved (no shuffling) | **PASS** |
| **Storage Format Verification** | Apache Parquet (Snappy) | 8 valid Parquet files in `processed/final_features/` | **PASS** |

---

## 15. Preprocessing Pipeline Summary

Here is the complete sequence of steps from start to finish:

```
[ Raw CSE-CIC-IDS2018 CSV Files ] (2,830,743 rows, 78 features)
               │
               ▼
[ 1. Data Cleaning ]
   └── Remove 2,867 zero-duration flows (eliminates all NaNs & Infs)
   └── Fix label text encoding artifacts
               │
               ▼
[ 2. Duplicate Removal ]
   └── Drop 255,236 exact duplicate rows (preserves 2,572,640 unique flows)
   └── Preserve natural chronological row order
               │
               ▼
[ 3. Feature Analysis ]
   └── Inspect distributions, correlations, constant features, and negative values
               │
               ▼
[ 4. Redundant Feature Removal ]
   └── Drop 8 constant columns (all zero)
   └── Drop 8 exact mathematical duplicate columns
               │
               ▼
[ 5. Correction of Invalid Values ]
   └── Correct negative flow durations and recalculate rates
   └── Clip microsecond IAT measurement jitter to 0
   └── Restore 32-bit underflow header lengths using valid TCP sizes
               │
               ▼
[ 6. Sentinel Value Handling ]
   └── Decompose TCP window -1 values into presence flags and clean window sizes
               │
               ▼
[ 7. Skew Transformation ]
   └── Apply log1p(x) to heavy right-skewed continuous metrics
               │
               ▼
[ 8. Feature Engineering ]
   └── Derive destination_port_group service categories
   └── Create is_anomaly evaluation label (0 = Benign, 1 = Attack)
               │
               ▼
[ 9. Multi-Signal Organization ]
   └── Partition 63 modeling features into 5 behavioral signal groups:
       (Volume & Size, Rate & Velocity, Temporal/IAT, TCP Flags, Activity/Silence)
               │
               ▼
[ Final Model-Ready Dataset ] (2,572,640 flows, 67 columns, Snappy Parquet)
```

---

## 16. What Happens Next

> **Preprocessing is now complete.**  
> The dataset is clean, structurally sound, and saved in optimized Parquet files.

The next stages of the project are:
1. **Big Data Storage & Ingestion**: Store the cleaned Parquet files into HDFS and load them using Apache Spark for distributed computation.
2. **Signal-Specific Anomaly Detection**: Train Isolation Forest models on each behavioral signal group to produce signal-specific anomaly scores.
3. **Multi-Signal Integration**: Combine the scores across the 5 signal groups to detect subtle anomalies that cross different behavioral dimensions.
4. **Self-Tuning Thresholding**: Implement an adaptive threshold that automatically tunes itself to shifting traffic baselines over time.
5. **Evaluation**: Benchmark detection accuracy (ROC-AUC, Precision, Recall, and False Alarm Rate) against standard static thresholds.

---

## 17. One-Minute Explanation of Our Preprocessing

*(Use these 6 simple sentences to explain this stage during your viva or presentation)*:

1. *"We started with 2.83 million raw network flows from the CSE-CIC-IDS2018 benchmark across 8 daily capture files."*
2. *"First, we cleaned broken measurement flows and removed 255,000 duplicate records, leaving exactly 2.57 million clean, unique flows with zero missing or infinite values."*
3. *"Next, we analyzed all 78 numerical features and safely removed 16 features that were either completely constant or exact mathematical duplicates."*
4. *"We then fixed known network capture bugs, such as negative durations and header underflows, and decomposed `-1` sentinel values into clean indicators without throwing away valid data."*
5. *"We applied a logarithmic transformation to smooth out extreme outliers and created a practical service category for destination ports to avoid memorizing lab IP addresses."*
6. *"Finally, we organized our 63 clean features into 5 distinct behavioral signal groups—Volume, Rate, Timing, Protocol Flags, and Activity—and saved the final dataset into compressed Parquet files ready for Spark and our Multi-Signal Self-Tuning Threshold model."*
