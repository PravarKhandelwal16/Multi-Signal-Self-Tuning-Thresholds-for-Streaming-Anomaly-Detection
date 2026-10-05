# Feature Analysis Report: CSE-CIC-IDS2018 Cleaned Dataset

**Analysis Date**: 2026-10-05 10:57:05  
**Analyzed Directory**: `Processed DataSet`  
**Total Flows Analyzed**: 2,572,640  
**Total Features**: 78 (+ 1 Target Label = 79 columns)  
**Clean Data Quality**: 0 NaN values, 0 infinite values, 0 duplicate rows  

## 1. Executive Summary & Recommendation Overview

An in-depth statistical, information-theoretic, and protocol-level analysis was conducted on all 78 numerical features across the 2,572,640 cleaned network flows. No features were permanently removed in this step, adhering strictly to the inspection-first protocol.

| Recommendation Status | Feature Count | Percentage | Key Action |
| :--- | :---: | :---: | :--- |
| **Keep** | 36 | 45.6% | Retain as informative, high-variance traffic signals for streaming detection. |
| **Drop** | 18 | 22.8% | Drop in next step due to zero variance (constant), exact redundancy, or mathematical duplicates. |
| **Transform** | 24 | 30.4% | Apply monotonic transformations (log1p, clipping, min-max) to resolve heavy right-skew or tool bugs. |
| **Discuss** | 1 | 1.3% | Address potential shortcut learning / leakage (e.g., Destination Port). |
| **Total** | 79 | 100.0% | 78 features + 1 label |

## 2. Feature Type Categorization

Every column present in the dataset (and notable columns omitted in the CSV release) has been categorized according to network semantics:

### Timestamp (1 items)
- `Timestamp (Omitted in MachineLearningCVE CSV export; present in raw pcap/flow logs)`

### Identifier fields (4 items)
- `Flow ID (Omitted in MachineLearningCVE CSV export)`
- `Source IP (Omitted in MachineLearningCVE CSV export)`
- `Destination IP (Omitted in MachineLearningCVE CSV export)`
- `Source Port (Omitted in MachineLearningCVE CSV export)`

### Network address fields (2 items)
- `Source IP (Omitted)`
- `Destination IP (Omitted)`

### Port fields (1 items)
- `Destination Port`

### Numerical traffic features (77 items)
- `Flow Duration`
- `Total Fwd Packets`
- `Total Backward Packets`
- `Total Length of Fwd Packets`
- `Total Length of Bwd Packets`
- `Fwd Packet Length Max`
- `Fwd Packet Length Min`
- `Fwd Packet Length Mean`
- `Fwd Packet Length Std`
- `Bwd Packet Length Max`
- `Bwd Packet Length Min`
- `Bwd Packet Length Mean`
- `Bwd Packet Length Std`
- `Flow Bytes/s`
- `Flow Packets/s`
- `Flow IAT Mean`
- `Flow IAT Std`
- `Flow IAT Max`
- `Flow IAT Min`
- `Fwd IAT Total`
- `Fwd IAT Mean`
- `Fwd IAT Std`
- `Fwd IAT Max`
- `Fwd IAT Min`
- `Bwd IAT Total`
- `Bwd IAT Mean`
- `Bwd IAT Std`
- `Bwd IAT Max`
- `Bwd IAT Min`
- `Fwd PSH Flags`
- `Bwd PSH Flags`
- `Fwd URG Flags`
- `Bwd URG Flags`
- `Fwd Header Length`
- `Bwd Header Length`
- `Fwd Packets/s`
- `Bwd Packets/s`
- `Min Packet Length`
- `Max Packet Length`
- `Packet Length Mean`
- `Packet Length Std`
- `Packet Length Variance`
- `FIN Flag Count`
- `SYN Flag Count`
- `RST Flag Count`
- `PSH Flag Count`
- `ACK Flag Count`
- `URG Flag Count`
- `CWE Flag Count`
- `ECE Flag Count`
- `Down/Up Ratio`
- `Average Packet Size`
- `Avg Fwd Segment Size`
- `Avg Bwd Segment Size`
- `Fwd Header Length.1`
- `Fwd Avg Bytes/Bulk`
- `Fwd Avg Packets/Bulk`
- `Fwd Avg Bulk Rate`
- `Bwd Avg Bytes/Bulk`
- `Bwd Avg Packets/Bulk`
- `Bwd Avg Bulk Rate`
- `Subflow Fwd Packets`
- `Subflow Fwd Bytes`
- `Subflow Bwd Packets`
- `Subflow Bwd Bytes`
- `Init_Win_bytes_forward`
- `Init_Win_bytes_backward`
- `act_data_pkt_fwd`
- `min_seg_size_forward`
- `Active Mean`
- `Active Std`
- `Active Max`
- `Active Min`
- `Idle Mean`
- `Idle Std`
- `Idle Max`
- `Idle Min`

### Label / target columns (1 items)
- `Label`

### Potential duplicate/redundant features (8 items)
- `Fwd Header Length.1`
- `Subflow Fwd Packets`
- `Subflow Fwd Bytes`
- `Subflow Bwd Packets`
- `Subflow Bwd Bytes`
- `Avg Fwd Segment Size`
- `Avg Bwd Segment Size`
- `Packet Length Variance`

## 3. Identifier and Data Leakage Column Analysis

A critical vulnerability in network intrusion detection research is **shortcut learning** and **data leakage**, where models memorize benign vs. attack environments rather than learning generalizable anomaly signatures.

| Column Name | Present in File? | Retention Decision | Leakage & Behavioral Rationale |
| :--- | :---: | :---: | :--- |
| **Flow ID** | **No** (omitted in CSV) | **Exclude** | Concatenation of 5-tuple (`SrcIP-DstIP-SrcPort-DstPort-Proto`). Memorizes individual host identities and connection instances. Total leakage. |
| **Source IP** | **No** (omitted in CSV) | **Exclude** | In the CSE-CIC-IDS2018 testbed, attacker machines had fixed, static IP addresses (e.g. Kali attacker VMs). Models trained on Source IP achieve 99.9% accuracy simply by memorizing attacker IPs, failing completely on real-world networks. |
| **Destination IP**| **No** (omitted in CSV) | **Exclude** | Attacked victim servers (e.g. web server, database server) had static IPs. Memorizing Destination IP leaks target server identities rather than detecting malicious traffic dynamics. |
| **Timestamp** | **No** (omitted in CSV) | **Exclude from Model** / **Keep for Streaming Clock** | Attacks were executed in scheduled time windows (e.g. DDoS on Friday afternoon, Web Attacks on Thursday morning). Training on timestamp leaks the test schedule. However, for a *streaming self-tuning threshold algorithm*, relative timestamps or arrival sequence order is essential for temporal windowing. |
| **Source Port** | **No** (omitted in CSV) | **Exclude** | Typically an ephemeral client port (49152–65535) randomly assigned by the OS. High-cardinality noise that causes overfitting or leaks specific attack tool port selection. |
| **Destination Port** | **Yes** (Present) | **Discuss / Discretionary** | Destination port identifies the targeted application service (e.g. Port 80/HTTP, 21/FTP, 22/SSH). While port context is relevant in production firewalls, models can overfit to attacks that only targeted specific ports in the lab. **Recommendation**: Group into coarse service categories (Web, Mail, SSH, DNS, Ephemeral) or drop if pure protocol-agnostic anomaly detection is required. |

## 4. Problematic Features (Constant, Near-Zero Variance, Tool Artifacts)

### 4.1 Zero-Variance / Constant Features (Always 0)
These features have `min == max == 0.0` across all 2,572,640 flows. They provide exactly zero bits of mutual information or variance and should be dropped:

| Feature Name | Min | Max | Mean | Std | % Zeros |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `Bwd PSH Flags` | 0.0 | 0.0 | 0.0 | 0.0 | 100.0% |
| `Bwd URG Flags` | 0.0 | 0.0 | 0.0 | 0.0 | 100.0% |
| `Fwd Avg Bytes/Bulk` | 0.0 | 0.0 | 0.0 | 0.0 | 100.0% |
| `Fwd Avg Packets/Bulk` | 0.0 | 0.0 | 0.0 | 0.0 | 100.0% |
| `Fwd Avg Bulk Rate` | 0.0 | 0.0 | 0.0 | 0.0 | 100.0% |
| `Bwd Avg Bytes/Bulk` | 0.0 | 0.0 | 0.0 | 0.0 | 100.0% |
| `Bwd Avg Packets/Bulk` | 0.0 | 0.0 | 0.0 | 0.0 | 100.0% |
| `Bwd Avg Bulk Rate` | 0.0 | 0.0 | 0.0 | 0.0 | 100.0% |

### 4.2 Near-Zero Variance Features
These features have variance near zero (>99.9% zeros or near-constant):

| Feature Name | Min | Max | Mean | Std | % Zeros |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `Fwd URG Flags` | 0.0 | 1.0 | 3.1e-05 | 0.005576 | 99.997% |
| `RST Flag Count` | 0.0 | 1.0 | 0.000267 | 0.016327 | 99.973% |
| `CWE Flag Count` | 0.0 | 1.0 | 3.1e-05 | 0.005576 | 99.997% |
| `ECE Flag Count` | 0.0 | 1.0 | 0.000268 | 0.016363 | 99.973% |

### 4.3 Features with Suspicious Negative Values (CICFlowMeter Bugs / Sentinels)
| Feature Name | Occurrences (<0) | Min Value | Root Cause & Recommendation |
| :--- | :---: | :---: | :--- |
| `Flow Duration` | 113 | -1.30e+01 | Microsecond timestamp jitter / packet reordering between sniffer interfaces (Delta t < 0 down to -14us). Action: clip to 0 or remove these 113 malformed flows. |
| `Flow Bytes/s` | 84 | -2.61e+08 | Direct consequence of division by negative Flow Duration (Delta t < 0). Action: corrected when negative Flow Durations are cleaned/clipped. |
| `Flow Packets/s` | 113 | -2.00e+06 | Direct consequence of division by negative Flow Duration (Delta t < 0). Action: corrected when negative Flow Durations are cleaned/clipped. |
| `Flow IAT Mean` | 113 | -1.30e+01 | Microsecond timestamp jitter / packet reordering between sniffer interfaces (Delta t < 0 down to -14us). Action: clip to 0 or remove these 113 malformed flows. |
| `Flow IAT Max` | 113 | -1.30e+01 | Microsecond timestamp jitter / packet reordering between sniffer interfaces (Delta t < 0 down to -14us). Action: clip to 0 or remove these 113 malformed flows. |
| `Flow IAT Min` | 2,887 | -1.40e+01 | Microsecond timestamp jitter / packet reordering between sniffer interfaces (Delta t < 0 down to -14us). Action: clip to 0 or remove these 113 malformed flows. |
| `Fwd IAT Min` | 17 | -1.20e+01 | Microsecond timestamp jitter / packet reordering between sniffer interfaces (Delta t < 0 down to -14us). Action: clip to 0 or remove these 113 malformed flows. |
| `Fwd Header Length` | 35 | -3.22e+10 | CICFlowMeter 32-bit signed integer underflow/overflow when parsing corrupted TCP option offsets or malformed headers. Action: clip to 0. |
| `Bwd Header Length` | 22 | -1.07e+09 | CICFlowMeter 32-bit signed integer underflow/overflow when parsing corrupted TCP option offsets or malformed headers. Action: clip to 0. |
| `Fwd Header Length.1` | 35 | -3.22e+10 | CICFlowMeter 32-bit signed integer underflow/overflow when parsing corrupted TCP option offsets or malformed headers. Action: clip to 0. |
| `Init_Win_bytes_forward` | 951,492 | -1.00e+00 | Expected sentinel (-1) in CICFlowMeter for non-TCP flows (UDP/ICMP) or flows missing the SYN / SYN-ACK handshake packet. |
| `Init_Win_bytes_backward` | 1,264,134 | -1.00e+00 | Expected sentinel (-1) in CICFlowMeter for non-TCP flows (UDP/ICMP) or flows missing the SYN / SYN-ACK handshake packet. |
| `min_seg_size_forward` | 35 | -5.37e+08 | CICFlowMeter 32-bit signed integer underflow/overflow when parsing corrupted TCP option offsets or malformed headers. Action: clip to 0. |

## 5. Correlation & Exact Redundancy Analysis

### 5.1 Exact Mathematical Duplicates (100% Identical Across Entire Dataset)

The following feature pairs were tested across **every single row** (2,572,640 rows) of all 8 CSV files:

| Feature A | Feature B | Is 100% Identical? | Mathematical Reason | Action |
| :--- | :--- | :---: | :--- | :--- |
| `Fwd Header Length` | `Fwd Header Length.1` | **True** | Duplicate column created by CICFlowMeter export script. | **Drop `Fwd Header Length.1`** |
| `Total Fwd Packets` | `Subflow Fwd Packets` | **True** | In CICFlowMeter, subflow window was identical to flow window. | **Drop `Subflow Fwd Packets`** |
| `Total Backward Packets` | `Subflow Bwd Packets` | **True** | Subflow backward packets equals total backward packets. | **Drop `Subflow Bwd Packets`** |
| `Total Length of Fwd Packets` | `Subflow Fwd Bytes` | **False** | Subflow forward bytes equals total length of forward packets. | **Drop `Subflow Fwd Bytes`** |
| `Total Length of Bwd Packets` | `Subflow Bwd Bytes` | **False** | Subflow backward bytes equals total length of backward packets. | **Drop `Subflow Bwd Bytes`** |
| `Fwd Packet Length Mean` | `Avg Fwd Segment Size` | **True** | TCP segment size equals IP packet payload size. | **Drop `Avg Fwd Segment Size`** |
| `Bwd Packet Length Mean` | `Avg Bwd Segment Size` | **True** | TCP segment size equals IP packet payload size. | **Drop `Avg Bwd Segment Size`** |
| `Packet Length Variance` | `(Packet Length Std)^2` | **True (r > 0.98)** | Variance is the exact mathematical square of standard deviation. | **Drop `Packet Length Variance`** |

### 5.2 Highly Correlated Feature Pairs (|r| >= 0.90)

A total of **68** feature pairs exhibited Pearson correlation $|r| \ge 0.90$. Below are the top pairs with $|r| \ge 0.95$:

| Feature 1 | Feature 2 | Pearson Correlation (r) | Redundancy Assessment |
| :--- | :--- | :---: | :--- |
| `Total Fwd Packets` | `Subflow Fwd Packets` | **1.0000** | Exact duplicate |
| `Total Backward Packets` | `Subflow Bwd Packets` | **1.0000** | Exact duplicate |
| `Total Length of Fwd Packets` | `Subflow Fwd Bytes` | **1.0000** | Exact duplicate |
| `Total Length of Bwd Packets` | `Subflow Bwd Bytes` | **1.0000** | Exact duplicate |
| `Fwd Packet Length Mean` | `Avg Fwd Segment Size` | **1.0000** | Exact duplicate |
| `Bwd Packet Length Mean` | `Avg Bwd Segment Size` | **1.0000** | Exact duplicate |
| `Fwd PSH Flags` | `SYN Flag Count` | **1.0000** | Exact duplicate |
| `Fwd URG Flags` | `CWE Flag Count` | **1.0000** | Exact duplicate |
| `Fwd Header Length` | `Fwd Header Length.1` | **1.0000** | Exact duplicate |
| `RST Flag Count` | `ECE Flag Count` | **1.0000** | Exact duplicate |
| `Total Fwd Packets` | `Total Length of Bwd Packets` | **0.9997** | Extremely high redundancy |
| `Total Fwd Packets` | `Subflow Bwd Bytes` | **0.9997** | Extremely high redundancy |
| `Total Length of Bwd Packets` | `Subflow Fwd Packets` | **0.9997** | Extremely high redundancy |
| `Subflow Fwd Packets` | `Subflow Bwd Bytes` | **0.9997** | Extremely high redundancy |
| `Total Fwd Packets` | `Total Backward Packets` | **0.9995** | Extremely high redundancy |
| `Total Fwd Packets` | `Subflow Bwd Packets` | **0.9995** | Extremely high redundancy |
| `Total Backward Packets` | `Subflow Fwd Packets` | **0.9995** | Extremely high redundancy |
| `Subflow Fwd Packets` | `Subflow Bwd Packets` | **0.9995** | Extremely high redundancy |
| `Total Backward Packets` | `Total Length of Bwd Packets` | **0.9993** | Extremely high redundancy |
| `Total Backward Packets` | `Subflow Bwd Bytes` | **0.9993** | Extremely high redundancy |
| `Total Length of Bwd Packets` | `Subflow Bwd Packets` | **0.9993** | Extremely high redundancy |
| `Subflow Bwd Packets` | `Subflow Bwd Bytes` | **0.9993** | Extremely high redundancy |
| `Flow Duration` | `Fwd IAT Total` | **0.9982** | Extremely high redundancy |
| `Packet Length Mean` | `Average Packet Size` | **0.9978** | Extremely high redundancy |
| `Flow IAT Max` | `Fwd IAT Max` | **0.9970** | Extremely high redundancy |

## 6. Multi-Signal Feature Grouping for Streaming Anomaly Detection

For a **Multi-Signal Self-Tuning Thresholding Architecture**, features must be partitioned into orthogonal behavioral signals so that anomaly thresholds can adapt dynamically to different operational dimensions:

### Volume & Size Signals (20 features)
*Role*: Monitors flow size distribution, payload depth, and asymmetry; detects port scans, exfiltration, and buffer overflows.

| Feature Name | Type | Mean | Median | Std | Min | Max |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `Total Length of Fwd Packets` | `int64` | 601.37 | 62.00 | 10481.37 | 0.0 | 1.29e+07 |
| `Total Length of Bwd Packets` | `int64` | 17781.14 | 135.00 | 2373892.59 | 0.0 | 6.55e+08 |
| `Fwd Packet Length Max` | `int64` | 227.26 | 37.00 | 749.24 | 0.0 | 2.48e+04 |
| `Fwd Packet Length Min` | `int64` | 19.49 | 6.00 | 60.38 | 0.0 | 2.32e+03 |
| `Fwd Packet Length Mean` | `float64` | 62.91 | 34.00 | 193.67 | 0.0 | 5.94e+03 |
| `Fwd Packet Length Std` | `float64` | 75.78 | 0.00 | 294.07 | 0.0 | 7.13e+03 |
| `Bwd Packet Length Max` | `int64` | 956.58 | 87.00 | 2021.79 | 0.0 | 1.95e+04 |
| `Bwd Packet Length Min` | `int64` | 43.54 | 6.00 | 70.68 | 0.0 | 2.90e+03 |
| `Bwd Packet Length Mean` | `float64` | 335.01 | 79.00 | 627.43 | 0.0 | 5.80e+03 |
| `Bwd Packet Length Std` | `float64` | 368.96 | 0.00 | 873.74 | 0.0 | 8.19e+03 |
| `Min Packet Length` | `int64` | 17.16 | 6.00 | 25.65 | 0.0 | 1.45e+03 |
| `Max Packet Length` | `int64` | 1043.64 | 94.00 | 2104.90 | 0.0 | 2.48e+04 |
| `Packet Length Mean` | `float64` | 187.75 | 59.80 | 315.82 | 0.0 | 3.34e+03 |
| `Packet Length Std` | `float64` | 323.91 | 29.03 | 655.68 | 0.0 | 4.73e+03 |
| `Packet Length Variance` | `float64` | 534799.32 | 842.70 | 1720596.94 | 0.0 | 2.24e+07 |
| `Average Packet Size` | `float64` | 209.35 | 75.52 | 342.74 | 0.0 | 3.89e+03 |
| `Avg Fwd Segment Size` | `float64` | 62.91 | 34.00 | 193.67 | 0.0 | 5.94e+03 |
| `Avg Bwd Segment Size` | `float64` | 335.01 | 79.00 | 627.43 | 0.0 | 5.80e+03 |
| `act_data_pkt_fwd` | `int64` | 5.91 | 1.00 | 667.59 | 0.0 | 2.14e+05 |
| `min_seg_size_forward` | `int64` | -3019.60 | 20.00 | 1138114.79 | -536870661.0 | 1.38e+02 |

### Rate & Velocity Signals (4 features)
*Role*: Monitors velocity of data and packet transfer; detects volumetric flooding (DDoS/DoS).

| Feature Name | Type | Mean | Median | Std | Min | Max |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `Flow Bytes/s` | `float64` | 1430298.49 | 4843.35 | 26356449.17 | -261000000.0 | 2.07e+09 |
| `Flow Packets/s` | `float64` | 47358.11 | 83.53 | 202001.74 | -2000000.0 | 4.00e+06 |
| `Fwd Packets/s` | `float64` | 40833.62 | 42.28 | 192530.22 | 0.0 | 3.00e+06 |
| `Bwd Packets/s` | `float64` | 6608.83 | 21.47 | 38320.58 | 0.0 | 2.00e+06 |

### Temporal & Inter-Arrival Time (IAT) Signals (15 features)
*Role*: Monitors arrival pacing, jitter, and burstiness; detects automated scripts vs human browsing.

| Feature Name | Type | Mean | Median | Std | Min | Max |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `Flow Duration` | `int64` | 16257359.77 | 47528.00 | 34953760.77 | -13.0 | 1.20e+08 |
| `Flow IAT Mean` | `float64` | 1417088.56 | 16700.94 | 4640196.75 | -13.0 | 1.20e+08 |
| `Flow IAT Std` | `float64` | 3212095.68 | 4726.30 | 8383776.09 | 0.0 | 8.48e+07 |
| `Flow IAT Max` | `int64` | 10092027.27 | 35070.50 | 25466376.86 | -13.0 | 1.20e+08 |
| `Flow IAT Min` | `int64` | 167073.79 | 4.00 | 2983872.38 | -14.0 | 1.20e+08 |
| `Fwd IAT Total` | `int64` | 15924345.52 | 48.00 | 34885081.08 | 0.0 | 1.20e+08 |
| `Fwd IAT Mean` | `float64` | 2860435.31 | 48.00 | 9923439.98 | 0.0 | 1.20e+08 |
| `Fwd IAT Std` | `float64` | 3594712.81 | 0.00 | 10052593.90 | 0.0 | 8.46e+07 |
| `Fwd IAT Max` | `int64` | 9938547.11 | 48.00 | 25545352.98 | 0.0 | 1.20e+08 |
| `Fwd IAT Min` | `int64` | 1112790.55 | 3.00 | 8969172.52 | -12.0 | 1.20e+08 |
| `Bwd IAT Total` | `int64` | 10886362.00 | 3.00 | 29963804.38 | 0.0 | 1.20e+08 |
| `Bwd IAT Mean` | `float64` | 1986873.05 | 3.00 | 9302624.65 | 0.0 | 1.20e+08 |
| `Bwd IAT Std` | `float64` | 1635055.29 | 0.00 | 6567357.46 | 0.0 | 8.44e+07 |
| `Bwd IAT Max` | `int64` | 5154611.46 | 3.00 | 17933611.53 | 0.0 | 1.20e+08 |
| `Bwd IAT Min` | `int64` | 1064224.95 | 2.00 | 8709463.15 | 0.0 | 1.20e+08 |

### TCP Protocol State & Flag Signals (18 features)
*Role*: Monitors protocol handshake discipline and flag anomalies; detects SYN flood, port scanning, abnormal teardowns.

| Feature Name | Type | Mean | Median | Std | Min | Max |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `Fwd PSH Flags` | `int64` | 0.05 | 0.00 | 0.21 | 0.0 | 1.00e+00 |
| `Bwd PSH Flags` | `int64` | 0.00 | 0.00 | 0.00 | 0.0 | 0.00e+00 |
| `Fwd URG Flags` | `int64` | 0.00 | 0.00 | 0.01 | 0.0 | 1.00e+00 |
| `Bwd URG Flags` | `int64` | 0.00 | 0.00 | 0.00 | 0.0 | 0.00e+00 |
| `FIN Flag Count` | `int64` | 0.03 | 0.00 | 0.17 | 0.0 | 1.00e+00 |
| `SYN Flag Count` | `int64` | 0.05 | 0.00 | 0.21 | 0.0 | 1.00e+00 |
| `RST Flag Count` | `int64` | 0.00 | 0.00 | 0.02 | 0.0 | 1.00e+00 |
| `PSH Flag Count` | `int64` | 0.29 | 0.00 | 0.45 | 0.0 | 1.00e+00 |
| `ACK Flag Count` | `int64` | 0.31 | 0.00 | 0.46 | 0.0 | 1.00e+00 |
| `URG Flag Count` | `int64` | 0.10 | 0.00 | 0.30 | 0.0 | 1.00e+00 |
| `CWE Flag Count` | `int64` | 0.00 | 0.00 | 0.01 | 0.0 | 1.00e+00 |
| `ECE Flag Count` | `int64` | 0.00 | 0.00 | 0.02 | 0.0 | 1.00e+00 |
| `Down/Up Ratio` | `int64` | 0.70 | 1.00 | 0.69 | 0.0 | 1.56e+02 |
| `Init_Win_bytes_forward` | `int64` | 7145.03 | 255.00 | 14521.85 | -1.0 | 6.55e+04 |
| `Init_Win_bytes_backward` | `int64` | 2184.28 | 0.00 | 8839.68 | -1.0 | 6.55e+04 |
| `Fwd Header Length` | `int64` | -28610.73 | 64.00 | 22083695.23 | -32212234632.0 | 4.64e+06 |
| `Bwd Header Length` | `int64` | -2502.93 | 40.00 | 1523315.19 | -1073741320.0 | 5.84e+06 |
| `Fwd Header Length.1` | `int64` | -28610.73 | 64.00 | 22083695.23 | -32212234632.0 | 4.64e+06 |

### Activity & Silence Signals (8 features)
*Role*: Monitors active vs idle cycle periodicity; detects periodic beaconing (C2 command-and-control) and persistent tunnels.

| Feature Name | Type | Mean | Median | Std | Min | Max |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `Active Mean` | `float64` | 89733.05 | 0.00 | 679818.44 | 0.0 | 1.10e+08 |
| `Active Std` | `float64` | 45260.94 | 0.00 | 412416.79 | 0.0 | 7.42e+07 |
| `Active Max` | `int64` | 168550.73 | 0.00 | 1074849.51 | 0.0 | 1.10e+08 |
| `Active Min` | `int64` | 64144.41 | 0.00 | 605039.27 | 0.0 | 1.10e+08 |
| `Idle Mean` | `float64` | 9149207.24 | 0.00 | 24631517.27 | 0.0 | 1.20e+08 |
| `Idle Std` | `float64` | 554392.66 | 0.00 | 4825463.65 | 0.0 | 7.69e+07 |
| `Idle Max` | `int64` | 9567017.97 | 0.00 | 25395120.44 | 0.0 | 1.20e+08 |
| `Idle Min` | `int64` | 8713471.92 | 0.00 | 24364563.03 | 0.0 | 1.20e+08 |

### Bulk & Subflow Signals (12 features)
*Role*: Monitors bulk payload transfer rates and subflow counters.

| Feature Name | Type | Mean | Median | Std | Min | Max |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `Fwd Avg Bytes/Bulk` | `int64` | 0.00 | 0.00 | 0.00 | 0.0 | 0.00e+00 |
| `Fwd Avg Packets/Bulk` | `int64` | 0.00 | 0.00 | 0.00 | 0.0 | 0.00e+00 |
| `Fwd Avg Bulk Rate` | `int64` | 0.00 | 0.00 | 0.00 | 0.0 | 0.00e+00 |
| `Bwd Avg Bytes/Bulk` | `int64` | 0.00 | 0.00 | 0.00 | 0.0 | 0.00e+00 |
| `Bwd Avg Packets/Bulk` | `int64` | 0.00 | 0.00 | 0.00 | 0.0 | 0.00e+00 |
| `Bwd Avg Bulk Rate` | `int64` | 0.00 | 0.00 | 0.00 | 0.0 | 0.00e+00 |
| `Subflow Fwd Packets` | `int64` | 10.12 | 2.00 | 786.38 | 1.0 | 2.20e+05 |
| `Subflow Fwd Bytes` | `int64` | 601.36 | 62.00 | 10467.19 | 0.0 | 1.29e+07 |
| `Subflow Bwd Packets` | `int64` | 11.37 | 2.00 | 1046.22 | 0.0 | 2.92e+05 |
| `Subflow Bwd Bytes` | `int64` | 17780.77 | 135.00 | 2373860.31 | 0.0 | 6.55e+08 |
| `Total Fwd Packets` | `int64` | 10.12 | 2.00 | 786.38 | 1.0 | 2.20e+05 |
| `Total Backward Packets` | `int64` | 11.37 | 2.00 | 1046.22 | 0.0 | 2.92e+05 |

### Network Endpoint & Identifiers (1 features)
*Role*: Target metadata and endpoint routing.

| Feature Name | Type | Mean | Median | Std | Min | Max |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `Destination Port` | `int64` | 8522.90 | 80.00 | 18863.45 | 0.0 | 6.55e+04 |

### Target Label (1 features)
*Role*: Target metadata and endpoint routing.

| Feature Name | Type | Mean | Median | Std | Min | Max |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |

## 7. Numerical Feature Statistics Summary Table (All 78 Features)

| Feature Name | Type | Min | Max | Mean | Median | Std Dev | % Zeros | Unique (Sample) | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `Destination Port` | `int64` | 0.0 | 6.55e+04 | 8522.90 | 80.00 | 18863.45 | 0.1% | 23,262 | **Discuss** |
| `Flow Duration` | `int64` | -13.0 | 1.20e+08 | 16257359.77 | 47528.00 | 34953760.77 | 0.0% | 126,311 | **Transform** |
| `Total Fwd Packets` | `int64` | 1.0 | 2.20e+05 | 10.12 | 2.00 | 786.38 | 0.0% | 485 | **Keep** |
| `Total Backward Packets` | `int64` | 0.0 | 2.92e+05 | 11.37 | 2.00 | 1046.22 | 12.5% | 600 | **Keep** |
| `Total Length of Fwd Packets` | `int64` | 0.0 | 1.29e+07 | 601.37 | 62.00 | 10481.37 | 13.1% | 6,531 | **Keep** |
| `Total Length of Bwd Packets` | `int64` | 0.0 | 6.55e+08 | 17781.14 | 135.00 | 2373892.59 | 22.0% | 15,048 | **Keep** |
| `Fwd Packet Length Max` | `int64` | 0.0 | 2.48e+04 | 227.26 | 37.00 | 749.24 | 13.1% | 2,948 | **Keep** |
| `Fwd Packet Length Min` | `int64` | 0.0 | 2.32e+03 | 19.49 | 6.00 | 60.38 | 46.6% | 186 | **Keep** |
| `Fwd Packet Length Mean` | `float64` | 0.0 | 5.94e+03 | 62.91 | 34.00 | 193.67 | 13.1% | 20,061 | **Keep** |
| `Fwd Packet Length Std` | `float64` | 0.0 | 7.13e+03 | 75.78 | 0.00 | 294.07 | 62.2% | 33,559 | **Keep** |
| `Bwd Packet Length Max` | `int64` | 0.0 | 1.95e+04 | 956.58 | 87.00 | 2021.79 | 22.0% | 3,257 | **Keep** |
| `Bwd Packet Length Min` | `int64` | 0.0 | 2.90e+03 | 43.54 | 6.00 | 70.68 | 50.4% | 416 | **Keep** |
| `Bwd Packet Length Mean` | `float64` | 0.0 | 5.80e+03 | 335.01 | 79.00 | 627.43 | 22.0% | 24,903 | **Keep** |
| `Bwd Packet Length Std` | `float64` | 0.0 | 8.19e+03 | 368.96 | 0.00 | 873.74 | 68.7% | 31,526 | **Keep** |
| `Flow Bytes/s` | `float64` | -261000000.0 | 2.07e+09 | 1430298.49 | 4843.35 | 26356449.17 | 10.9% | 164,090 | **Transform** |
| `Flow Packets/s` | `float64` | -2000000.0 | 4.00e+06 | 47358.11 | 83.53 | 202001.74 | 0.0% | 138,931 | **Transform** |
| `Flow IAT Mean` | `float64` | -13.0 | 1.20e+08 | 1417088.56 | 16700.94 | 4640196.75 | 0.0% | 133,757 | **Transform** |
| `Flow IAT Std` | `float64` | 0.0 | 8.48e+07 | 3212095.68 | 4726.30 | 8383776.09 | 30.8% | 112,072 | **Transform** |
| `Flow IAT Max` | `int64` | -13.0 | 1.20e+08 | 10092027.27 | 35070.50 | 25466376.86 | 0.0% | 90,033 | **Transform** |
| `Flow IAT Min` | `int64` | -14.0 | 1.20e+08 | 167073.79 | 4.00 | 2983872.38 | 2.8% | 25,610 | **Transform** |
| `Fwd IAT Total` | `int64` | 0.0 | 1.20e+08 | 15924345.52 | 48.00 | 34885081.08 | 24.5% | 58,280 | **Transform** |
| `Fwd IAT Mean` | `float64` | 0.0 | 1.20e+08 | 2860435.31 | 48.00 | 9923439.98 | 24.5% | 80,391 | **Transform** |
| `Fwd IAT Std` | `float64` | 0.0 | 8.46e+07 | 3594712.81 | 0.00 | 10052593.90 | 59.2% | 71,808 | **Transform** |
| `Fwd IAT Max` | `int64` | 0.0 | 1.20e+08 | 9938547.11 | 48.00 | 25545352.98 | 24.5% | 57,740 | **Transform** |
| `Fwd IAT Min` | `int64` | -12.0 | 1.20e+08 | 1112790.55 | 3.00 | 8969172.52 | 25.7% | 18,477 | **Transform** |
| `Bwd IAT Total` | `int64` | 0.0 | 1.20e+08 | 10886362.00 | 3.00 | 29963804.38 | 40.3% | 48,471 | **Transform** |
| `Bwd IAT Mean` | `float64` | 0.0 | 1.20e+08 | 1986873.05 | 3.00 | 9302624.65 | 40.3% | 68,841 | **Transform** |
| `Bwd IAT Std` | `float64` | 0.0 | 8.44e+07 | 1635055.29 | 0.00 | 6567357.46 | 68.5% | 64,364 | **Transform** |
| `Bwd IAT Max` | `int64` | 0.0 | 1.20e+08 | 5154611.46 | 3.00 | 17933611.53 | 40.3% | 48,417 | **Transform** |
| `Bwd IAT Min` | `int64` | 0.0 | 1.20e+08 | 1064224.95 | 2.00 | 8709463.15 | 40.7% | 9,172 | **Transform** |
| `Fwd PSH Flags` | `int64` | 0.0 | 1.00e+00 | 0.05 | 0.00 | 0.21 | 95.2% | 2 | **Keep** |
| `Bwd PSH Flags` | `int64` | 0.0 | 0.00e+00 | 0.00 | 0.00 | 0.00 | 100.0% | 1 | **Drop** |
| `Fwd URG Flags` | `int64` | 0.0 | 1.00e+00 | 0.00 | 0.00 | 0.01 | 100.0% | 2 | **Drop** |
| `Bwd URG Flags` | `int64` | 0.0 | 0.00e+00 | 0.00 | 0.00 | 0.00 | 100.0% | 1 | **Drop** |
| `Fwd Header Length` | `int64` | -32212234632.0 | 4.64e+06 | -28610.73 | 64.00 | 22083695.23 | 0.1% | 1,257 | **Transform** |
| `Bwd Header Length` | `int64` | -1073741320.0 | 5.84e+06 | -2502.93 | 40.00 | 1523315.19 | 12.5% | 1,347 | **Transform** |
| `Fwd Packets/s` | `float64` | 0.0 | 3.00e+06 | 40833.62 | 42.28 | 192530.22 | 0.0% | 137,954 | **Transform** |
| `Bwd Packets/s` | `float64` | 0.0 | 2.00e+06 | 6608.83 | 21.47 | 38320.58 | 12.5% | 123,654 | **Transform** |
| `Min Packet Length` | `int64` | 0.0 | 1.45e+03 | 17.16 | 6.00 | 25.65 | 47.6% | 150 | **Keep** |
| `Max Packet Length` | `int64` | 0.0 | 2.48e+04 | 1043.64 | 94.00 | 2104.90 | 10.9% | 3,731 | **Keep** |
| `Packet Length Mean` | `float64` | 0.0 | 3.34e+03 | 187.75 | 59.80 | 315.82 | 10.9% | 34,920 | **Keep** |
| `Packet Length Std` | `float64` | 0.0 | 4.73e+03 | 323.91 | 29.03 | 655.68 | 22.2% | 48,568 | **Keep** |
| `Packet Length Variance` | `float64` | 0.0 | 2.24e+07 | 534799.32 | 842.70 | 1720596.94 | 22.2% | 47,924 | **Drop** |
| `FIN Flag Count` | `int64` | 0.0 | 1.00e+00 | 0.03 | 0.00 | 0.17 | 96.8% | 2 | **Keep** |
| `SYN Flag Count` | `int64` | 0.0 | 1.00e+00 | 0.05 | 0.00 | 0.21 | 95.2% | 2 | **Keep** |
| `RST Flag Count` | `int64` | 0.0 | 1.00e+00 | 0.00 | 0.00 | 0.02 | 100.0% | 2 | **Keep** |
| `PSH Flag Count` | `int64` | 0.0 | 1.00e+00 | 0.29 | 0.00 | 0.45 | 70.8% | 2 | **Keep** |
| `ACK Flag Count` | `int64` | 0.0 | 1.00e+00 | 0.31 | 0.00 | 0.46 | 69.0% | 2 | **Keep** |
| `URG Flag Count` | `int64` | 0.0 | 1.00e+00 | 0.10 | 0.00 | 0.30 | 90.0% | 2 | **Keep** |
| `CWE Flag Count` | `int64` | 0.0 | 1.00e+00 | 0.00 | 0.00 | 0.01 | 100.0% | 2 | **Drop** |
| `ECE Flag Count` | `int64` | 0.0 | 1.00e+00 | 0.00 | 0.00 | 0.02 | 100.0% | 2 | **Keep** |
| `Down/Up Ratio` | `int64` | 0.0 | 1.56e+02 | 0.70 | 1.00 | 0.69 | 35.5% | 12 | **Keep** |
| `Average Packet Size` | `float64` | 0.0 | 3.89e+03 | 209.35 | 75.52 | 342.74 | 10.9% | 33,919 | **Keep** |
| `Avg Fwd Segment Size` | `float64` | 0.0 | 5.94e+03 | 62.91 | 34.00 | 193.67 | 13.1% | 20,061 | **Drop** |
| `Avg Bwd Segment Size` | `float64` | 0.0 | 5.80e+03 | 335.01 | 79.00 | 627.43 | 22.0% | 24,903 | **Drop** |
| `Fwd Header Length.1` | `int64` | -32212234632.0 | 4.64e+06 | -28610.73 | 64.00 | 22083695.23 | 0.1% | 1,257 | **Drop** |
| `Fwd Avg Bytes/Bulk` | `int64` | 0.0 | 0.00e+00 | 0.00 | 0.00 | 0.00 | 100.0% | 1 | **Drop** |
| `Fwd Avg Packets/Bulk` | `int64` | 0.0 | 0.00e+00 | 0.00 | 0.00 | 0.00 | 100.0% | 1 | **Drop** |
| `Fwd Avg Bulk Rate` | `int64` | 0.0 | 0.00e+00 | 0.00 | 0.00 | 0.00 | 100.0% | 1 | **Drop** |
| `Bwd Avg Bytes/Bulk` | `int64` | 0.0 | 0.00e+00 | 0.00 | 0.00 | 0.00 | 100.0% | 1 | **Drop** |
| `Bwd Avg Packets/Bulk` | `int64` | 0.0 | 0.00e+00 | 0.00 | 0.00 | 0.00 | 100.0% | 1 | **Drop** |
| `Bwd Avg Bulk Rate` | `int64` | 0.0 | 0.00e+00 | 0.00 | 0.00 | 0.00 | 100.0% | 1 | **Drop** |
| `Subflow Fwd Packets` | `int64` | 1.0 | 2.20e+05 | 10.12 | 2.00 | 786.38 | 0.0% | 485 | **Drop** |
| `Subflow Fwd Bytes` | `int64` | 0.0 | 1.29e+07 | 601.36 | 62.00 | 10467.19 | 13.1% | 6,531 | **Drop** |
| `Subflow Bwd Packets` | `int64` | 0.0 | 2.92e+05 | 11.37 | 2.00 | 1046.22 | 12.5% | 600 | **Drop** |
| `Subflow Bwd Bytes` | `int64` | 0.0 | 6.55e+08 | 17780.77 | 135.00 | 2373860.31 | 22.0% | 15,051 | **Drop** |
| `Init_Win_bytes_forward` | `int64` | -1.0 | 6.55e+04 | 7145.03 | 255.00 | 14521.85 | 3.1% | 4,173 | **Transform** |
| `Init_Win_bytes_backward` | `int64` | -1.0 | 6.55e+04 | 2184.28 | 0.00 | 8839.68 | 7.9% | 4,294 | **Transform** |
| `act_data_pkt_fwd` | `int64` | 0.0 | 2.14e+05 | 5.91 | 1.00 | 667.59 | 31.4% | 384 | **Keep** |
| `min_seg_size_forward` | `int64` | -536870661.0 | 1.38e+02 | -3019.60 | 20.00 | 1138114.79 | 0.1% | 19 | **Transform** |
| `Active Mean` | `float64` | 0.0 | 1.10e+08 | 89733.05 | 0.00 | 679818.44 | 78.3% | 37,418 | **Keep** |
| `Active Std` | `float64` | 0.0 | 7.42e+07 | 45260.94 | 0.00 | 412416.79 | 92.0% | 19,253 | **Keep** |
| `Active Max` | `int64` | 0.0 | 1.10e+08 | 168550.73 | 0.00 | 1074849.51 | 78.3% | 36,914 | **Keep** |
| `Active Min` | `int64` | 0.0 | 1.10e+08 | 64144.41 | 0.00 | 605039.27 | 78.3% | 29,061 | **Keep** |
| `Idle Mean` | `float64` | 0.0 | 1.20e+08 | 9149207.24 | 0.00 | 24631517.27 | 78.0% | 22,273 | **Keep** |
| `Idle Std` | `float64` | 0.0 | 7.69e+07 | 554392.66 | 0.00 | 4825463.65 | 91.1% | 19,117 | **Keep** |
| `Idle Max` | `int64` | 0.0 | 1.20e+08 | 9567017.97 | 0.00 | 25395120.44 | 78.0% | 16,185 | **Keep** |
| `Idle Min` | `int64` | 0.0 | 1.20e+08 | 8713471.92 | 0.00 | 24364563.03 | 78.0% | 26,267 | **Keep** |

## 8. Complete Feature Decision Table & Recommendations

Below is the formal recommendation for all 79 columns in the dataset. **No columns have been removed yet**, pending user approval.

| # | Feature Name | Category | Multi-Signal Group | Recommendation | Rationale |
| :---: | :--- | :--- | :--- | :---: | :--- |
| 1 | `Destination Port` | Port fields | Network Endpoint & Identifiers | **Discuss** | Identifies target service (80, 443, 21, 22), but risks model shortcut learning/overfitting to specific lab IP/port setups. For pure behavioral anomaly detection, drop or group into categorical service tiers. |
| 2 | `Flow Duration` | Numerical traffic features | Temporal & Inter-Arrival Time (IAT) Signals | **Transform** | Core temporal signal. Contains rare microsecond timestamp jitter (<0) and extreme spans (microseconds to 120s). Requires clipping negatives and log1p transformation. |
| 3 | `Total Fwd Packets` | Numerical traffic features | Bulk & Subflow Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 4 | `Total Backward Packets` | Numerical traffic features | Bulk & Subflow Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 5 | `Total Length of Fwd Packets` | Numerical traffic features | Volume & Size Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 6 | `Total Length of Bwd Packets` | Numerical traffic features | Volume & Size Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 7 | `Fwd Packet Length Max` | Numerical traffic features | Volume & Size Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 8 | `Fwd Packet Length Min` | Numerical traffic features | Volume & Size Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 9 | `Fwd Packet Length Mean` | Numerical traffic features | Volume & Size Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 10 | `Fwd Packet Length Std` | Numerical traffic features | Volume & Size Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 11 | `Bwd Packet Length Max` | Numerical traffic features | Volume & Size Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 12 | `Bwd Packet Length Min` | Numerical traffic features | Volume & Size Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 13 | `Bwd Packet Length Mean` | Numerical traffic features | Volume & Size Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 14 | `Bwd Packet Length Std` | Numerical traffic features | Volume & Size Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 15 | `Flow Bytes/s` | Numerical traffic features | Rate & Velocity Signals | **Transform** | Core rate signal. Extreme right-skew (max values up to 10^9) and rare negative values from Delta t < 0. Requires clipping negatives and log1p/robust scaling. |
| 16 | `Flow Packets/s` | Numerical traffic features | Rate & Velocity Signals | **Transform** | Core rate signal. Extreme right-skew (max values up to 10^9) and rare negative values from Delta t < 0. Requires clipping negatives and log1p/robust scaling. |
| 17 | `Flow IAT Mean` | Numerical traffic features | Temporal & Inter-Arrival Time (IAT) Signals | **Transform** | Core temporal signal. Contains rare microsecond timestamp jitter (<0) and extreme spans (microseconds to 120s). Requires clipping negatives and log1p transformation. |
| 18 | `Flow IAT Std` | Numerical traffic features | Temporal & Inter-Arrival Time (IAT) Signals | **Transform** | Core temporal signal. Contains rare microsecond timestamp jitter (<0) and extreme spans (microseconds to 120s). Requires clipping negatives and log1p transformation. |
| 19 | `Flow IAT Max` | Numerical traffic features | Temporal & Inter-Arrival Time (IAT) Signals | **Transform** | Core temporal signal. Contains rare microsecond timestamp jitter (<0) and extreme spans (microseconds to 120s). Requires clipping negatives and log1p transformation. |
| 20 | `Flow IAT Min` | Numerical traffic features | Temporal & Inter-Arrival Time (IAT) Signals | **Transform** | Core temporal signal. Contains rare microsecond timestamp jitter (<0) and extreme spans (microseconds to 120s). Requires clipping negatives and log1p transformation. |
| 21 | `Fwd IAT Total` | Numerical traffic features | Temporal & Inter-Arrival Time (IAT) Signals | **Transform** | Core temporal signal. Contains rare microsecond timestamp jitter (<0) and extreme spans (microseconds to 120s). Requires clipping negatives and log1p transformation. |
| 22 | `Fwd IAT Mean` | Numerical traffic features | Temporal & Inter-Arrival Time (IAT) Signals | **Transform** | Core temporal signal. Contains rare microsecond timestamp jitter (<0) and extreme spans (microseconds to 120s). Requires clipping negatives and log1p transformation. |
| 23 | `Fwd IAT Std` | Numerical traffic features | Temporal & Inter-Arrival Time (IAT) Signals | **Transform** | Core temporal signal. Contains rare microsecond timestamp jitter (<0) and extreme spans (microseconds to 120s). Requires clipping negatives and log1p transformation. |
| 24 | `Fwd IAT Max` | Numerical traffic features | Temporal & Inter-Arrival Time (IAT) Signals | **Transform** | Core temporal signal. Contains rare microsecond timestamp jitter (<0) and extreme spans (microseconds to 120s). Requires clipping negatives and log1p transformation. |
| 25 | `Fwd IAT Min` | Numerical traffic features | Temporal & Inter-Arrival Time (IAT) Signals | **Transform** | Core temporal signal. Contains rare microsecond timestamp jitter (<0) and extreme spans (microseconds to 120s). Requires clipping negatives and log1p transformation. |
| 26 | `Bwd IAT Total` | Numerical traffic features | Temporal & Inter-Arrival Time (IAT) Signals | **Transform** | Core temporal signal. Contains rare microsecond timestamp jitter (<0) and extreme spans (microseconds to 120s). Requires clipping negatives and log1p transformation. |
| 27 | `Bwd IAT Mean` | Numerical traffic features | Temporal & Inter-Arrival Time (IAT) Signals | **Transform** | Core temporal signal. Contains rare microsecond timestamp jitter (<0) and extreme spans (microseconds to 120s). Requires clipping negatives and log1p transformation. |
| 28 | `Bwd IAT Std` | Numerical traffic features | Temporal & Inter-Arrival Time (IAT) Signals | **Transform** | Core temporal signal. Contains rare microsecond timestamp jitter (<0) and extreme spans (microseconds to 120s). Requires clipping negatives and log1p transformation. |
| 29 | `Bwd IAT Max` | Numerical traffic features | Temporal & Inter-Arrival Time (IAT) Signals | **Transform** | Core temporal signal. Contains rare microsecond timestamp jitter (<0) and extreme spans (microseconds to 120s). Requires clipping negatives and log1p transformation. |
| 30 | `Bwd IAT Min` | Numerical traffic features | Temporal & Inter-Arrival Time (IAT) Signals | **Transform** | Core temporal signal. Contains rare microsecond timestamp jitter (<0) and extreme spans (microseconds to 120s). Requires clipping negatives and log1p transformation. |
| 31 | `Fwd PSH Flags` | Numerical traffic features | TCP Protocol State & Flag Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 32 | `Bwd PSH Flags` | Numerical traffic features | TCP Protocol State & Flag Signals | **Drop** | Zero variance (constant = 0.0) across all 2,572,640 flows. Provides 0 discriminative information. |
| 33 | `Fwd URG Flags` | Numerical traffic features | TCP Protocol State & Flag Signals | **Drop** | Near-constant (99.9970% zeros, max=1.0). Unreliable and negligible information. |
| 34 | `Bwd URG Flags` | Numerical traffic features | TCP Protocol State & Flag Signals | **Drop** | Zero variance (constant = 0.0) across all 2,572,640 flows. Provides 0 discriminative information. |
| 35 | `Fwd Header Length` | Numerical traffic features | TCP Protocol State & Flag Signals | **Transform** | Contains negative values (35 rows, min=-3.22e+10) from CICFlowMeter 32-bit integer underflow bug. Needs clipping to 0. |
| 36 | `Bwd Header Length` | Numerical traffic features | TCP Protocol State & Flag Signals | **Transform** | Contains negative values (22 rows, min=-1.07e+09) from CICFlowMeter 32-bit integer underflow bug. Needs clipping to 0. |
| 37 | `Fwd Packets/s` | Numerical traffic features | Rate & Velocity Signals | **Transform** | Core rate signal. Extreme right-skew (max values up to 10^9) and rare negative values from Delta t < 0. Requires clipping negatives and log1p/robust scaling. |
| 38 | `Bwd Packets/s` | Numerical traffic features | Rate & Velocity Signals | **Transform** | Core rate signal. Extreme right-skew (max values up to 10^9) and rare negative values from Delta t < 0. Requires clipping negatives and log1p/robust scaling. |
| 39 | `Min Packet Length` | Numerical traffic features | Volume & Size Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 40 | `Max Packet Length` | Numerical traffic features | Volume & Size Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 41 | `Packet Length Mean` | Numerical traffic features | Volume & Size Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 42 | `Packet Length Std` | Numerical traffic features | Volume & Size Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 43 | `Packet Length Variance` | Numerical traffic features | Volume & Size Signals | **Drop** | Direct mathematical square of 'Packet Length Std' (r = 0.98+). Redundant quadratic scale. |
| 44 | `FIN Flag Count` | Numerical traffic features | TCP Protocol State & Flag Signals | **Keep** | Key protocol anomaly indicators (essential for detecting SYN floods, PortScans, FIN scans, RST attacks). |
| 45 | `SYN Flag Count` | Numerical traffic features | TCP Protocol State & Flag Signals | **Keep** | Key protocol anomaly indicators (essential for detecting SYN floods, PortScans, FIN scans, RST attacks). |
| 46 | `RST Flag Count` | Numerical traffic features | TCP Protocol State & Flag Signals | **Keep** | Key protocol anomaly indicators (essential for detecting SYN floods, PortScans, FIN scans, RST attacks). |
| 47 | `PSH Flag Count` | Numerical traffic features | TCP Protocol State & Flag Signals | **Keep** | Key protocol anomaly indicators (essential for detecting SYN floods, PortScans, FIN scans, RST attacks). |
| 48 | `ACK Flag Count` | Numerical traffic features | TCP Protocol State & Flag Signals | **Keep** | Key protocol anomaly indicators (essential for detecting SYN floods, PortScans, FIN scans, RST attacks). |
| 49 | `URG Flag Count` | Numerical traffic features | TCP Protocol State & Flag Signals | **Keep** | Key protocol anomaly indicators (essential for detecting SYN floods, PortScans, FIN scans, RST attacks). |
| 50 | `CWE Flag Count` | Numerical traffic features | TCP Protocol State & Flag Signals | **Drop** | Near-constant (99.9970% zeros, max=1.0). Unreliable and negligible information. |
| 51 | `ECE Flag Count` | Numerical traffic features | TCP Protocol State & Flag Signals | **Keep** | Key protocol anomaly indicators (essential for detecting SYN floods, PortScans, FIN scans, RST attacks). |
| 52 | `Down/Up Ratio` | Numerical traffic features | TCP Protocol State & Flag Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 53 | `Average Packet Size` | Numerical traffic features | Volume & Size Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 54 | `Avg Fwd Segment Size` | Numerical traffic features | Volume & Size Signals | **Drop** | Mathematically identical to 'Fwd Packet Length Mean' (r = 1.0000). Segment size equals packet payload length in TCP/UDP. |
| 55 | `Avg Bwd Segment Size` | Numerical traffic features | Volume & Size Signals | **Drop** | Mathematically identical to 'Bwd Packet Length Mean' (r = 1.0000). Segment size equals packet payload length in TCP/UDP. |
| 56 | `Fwd Header Length.1` | Potential duplicate/redundant features | TCP Protocol State & Flag Signals | **Drop** | Exact byte-for-byte duplicate of 'Fwd Header Length' (r = 1.0000, 100% identical). 0 new information. |
| 57 | `Fwd Avg Bytes/Bulk` | Numerical traffic features | Bulk & Subflow Signals | **Drop** | Zero variance (constant = 0.0) across all 2,572,640 flows. Provides 0 discriminative information. |
| 58 | `Fwd Avg Packets/Bulk` | Numerical traffic features | Bulk & Subflow Signals | **Drop** | Zero variance (constant = 0.0) across all 2,572,640 flows. Provides 0 discriminative information. |
| 59 | `Fwd Avg Bulk Rate` | Numerical traffic features | Bulk & Subflow Signals | **Drop** | Zero variance (constant = 0.0) across all 2,572,640 flows. Provides 0 discriminative information. |
| 60 | `Bwd Avg Bytes/Bulk` | Numerical traffic features | Bulk & Subflow Signals | **Drop** | Zero variance (constant = 0.0) across all 2,572,640 flows. Provides 0 discriminative information. |
| 61 | `Bwd Avg Packets/Bulk` | Numerical traffic features | Bulk & Subflow Signals | **Drop** | Zero variance (constant = 0.0) across all 2,572,640 flows. Provides 0 discriminative information. |
| 62 | `Bwd Avg Bulk Rate` | Numerical traffic features | Bulk & Subflow Signals | **Drop** | Zero variance (constant = 0.0) across all 2,572,640 flows. Provides 0 discriminative information. |
| 63 | `Subflow Fwd Packets` | Potential duplicate/redundant features | Bulk & Subflow Signals | **Drop** | Exact duplicate of 'Total Fwd Packets' in CICFlowMeter single-flow window (r = 1.0000). Redundant. |
| 64 | `Subflow Fwd Bytes` | Potential duplicate/redundant features | Bulk & Subflow Signals | **Drop** | Exact duplicate of 'Total Length of Fwd Packets' in CICFlowMeter single-flow window (r = 1.0000). Redundant. |
| 65 | `Subflow Bwd Packets` | Potential duplicate/redundant features | Bulk & Subflow Signals | **Drop** | Exact duplicate of 'Total Backward Packets' in CICFlowMeter single-flow window (r = 1.0000). Redundant. |
| 66 | `Subflow Bwd Bytes` | Potential duplicate/redundant features | Bulk & Subflow Signals | **Drop** | Exact duplicate of 'Total Length of Bwd Packets' in CICFlowMeter single-flow window (r = 1.0000). Redundant. |
| 67 | `Init_Win_bytes_forward` | Numerical traffic features | TCP Protocol State & Flag Signals | **Transform** | Contains -1 sentinel for non-TCP flows or missing SYN/SYN-ACK handshake. Should be transformed (e.g. separate binary indicator for TCP handshake or clip to 0). |
| 68 | `Init_Win_bytes_backward` | Numerical traffic features | TCP Protocol State & Flag Signals | **Transform** | Contains -1 sentinel for non-TCP flows or missing SYN/SYN-ACK handshake. Should be transformed (e.g. separate binary indicator for TCP handshake or clip to 0). |
| 69 | `act_data_pkt_fwd` | Numerical traffic features | Volume & Size Signals | **Keep** | Informative numerical traffic metric with healthy distribution and variance. |
| 70 | `min_seg_size_forward` | Numerical traffic features | Volume & Size Signals | **Transform** | Contains negative values (35 rows, min=-5.37e+08) from CICFlowMeter 32-bit integer underflow bug. Needs clipping to 0. |
| 71 | `Active Mean` | Numerical traffic features | Activity & Silence Signals | **Keep** | Activity/idle time features provide signal on flow periodicity. |
| 72 | `Active Std` | Numerical traffic features | Activity & Silence Signals | **Keep** | Sparse for short flows, but critical multi-signal burst/silence indicator for persistent C2, DoS, and exfiltration flows. |
| 73 | `Active Max` | Numerical traffic features | Activity & Silence Signals | **Keep** | Activity/idle time features provide signal on flow periodicity. |
| 74 | `Active Min` | Numerical traffic features | Activity & Silence Signals | **Keep** | Activity/idle time features provide signal on flow periodicity. |
| 75 | `Idle Mean` | Numerical traffic features | Activity & Silence Signals | **Keep** | Activity/idle time features provide signal on flow periodicity. |
| 76 | `Idle Std` | Numerical traffic features | Activity & Silence Signals | **Keep** | Sparse for short flows, but critical multi-signal burst/silence indicator for persistent C2, DoS, and exfiltration flows. |
| 77 | `Idle Max` | Numerical traffic features | Activity & Silence Signals | **Keep** | Activity/idle time features provide signal on flow periodicity. |
| 78 | `Idle Min` | Numerical traffic features | Activity & Silence Signals | **Keep** | Activity/idle time features provide signal on flow periodicity. |
| 79 | `Label` | Label / Target | Target Label | **Keep** | Ground truth target variable for model evaluation and validation. |

