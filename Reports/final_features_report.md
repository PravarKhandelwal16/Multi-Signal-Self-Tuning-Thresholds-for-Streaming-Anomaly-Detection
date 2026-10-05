# Final Feature Engineering Report: CSE-CIC-IDS2018

**Date**: 2026-10-05 11:04:31  
**Target Stage**: Isolation Forest Feature Space Preparation  
**Total Flows Processed**: 2,572,640 (Benign: 2,146,899, Anomalies: 425,741)  
**Total Parquet Output**: `processed\final_features` (8 Parquet files)  

## 1. Feature Count Overview

| Metric | Count | Details |
| :--- | :---: | :--- |
| **Original Raw Features** | 78 | All initial numerical features (excluding raw Label) |
| **Removed Redundant Features** | **16** | Confirmed constants (8) and exact duplicates (8) |
| **Derived / Engineered Features** | +5 | `destination_port_group`, `has_init_win_forward`, `init_win_bytes_forward_clean`, `has_init_win_backward`, `init_win_bytes_backward_clean` |
| **Retained Modeling Features** | **63** | High-variance, orthogonal features organized across 5 signal groups |
| **Context Features** | 2 | `Destination Port` (raw numeric) & `destination_port_group` (categorical) |
| **Evaluation Target Labels** | 2 | `Label` (ground truth string) & `is_anomaly` (binary 0/1) |
| **Total Final Schema Columns** | **67** | Saved in Snappy-compressed Parquet |

## 2. Removed Confirmed Redundant / Constant Features

The following 16 features were permanently excluded because they provide zero discriminative signal:

| # | Feature Name | Category | Removal Justification |
| :---: | :--- | :--- | :--- |
| 1 | `Bwd PSH Flags` | Redundant / Constant | Zero variance across all 2,572,640 flows (constant 0.0). |
| 2 | `Bwd URG Flags` | Redundant / Constant | Zero variance across all 2,572,640 flows (constant 0.0). |
| 3 | `Fwd Avg Bytes/Bulk` | Redundant / Constant | Zero variance across all 2,572,640 flows (constant 0.0). |
| 4 | `Fwd Avg Packets/Bulk` | Redundant / Constant | Zero variance across all 2,572,640 flows (constant 0.0). |
| 5 | `Fwd Avg Bulk Rate` | Redundant / Constant | Zero variance across all 2,572,640 flows (constant 0.0). |
| 6 | `Bwd Avg Bytes/Bulk` | Redundant / Constant | Zero variance across all 2,572,640 flows (constant 0.0). |
| 7 | `Bwd Avg Packets/Bulk` | Redundant / Constant | Zero variance across all 2,572,640 flows (constant 0.0). |
| 8 | `Bwd Avg Bulk Rate` | Redundant / Constant | Zero variance across all 2,572,640 flows (constant 0.0). |
| 9 | `Fwd Header Length.1` | Redundant / Constant | Exact byte-for-byte clone of `Fwd Header Length` (r = 1.0000). |
| 10 | `Subflow Fwd Packets` | Redundant / Constant | Exact duplicate of corresponding Total Flow counter in single-flow window (r = 1.0000). |
| 11 | `Subflow Fwd Bytes` | Redundant / Constant | Exact duplicate of corresponding Total Flow counter in single-flow window (r = 1.0000). |
| 12 | `Subflow Bwd Packets` | Redundant / Constant | Exact duplicate of corresponding Total Flow counter in single-flow window (r = 1.0000). |
| 13 | `Subflow Bwd Bytes` | Redundant / Constant | Exact duplicate of corresponding Total Flow counter in single-flow window (r = 1.0000). |
| 14 | `Avg Fwd Segment Size` | Redundant / Constant | Exact duplicate of corresponding Packet Length Mean (r = 1.0000). |
| 15 | `Avg Bwd Segment Size` | Redundant / Constant | Exact duplicate of corresponding Packet Length Mean (r = 1.0000). |
| 16 | `Packet Length Variance` | Redundant / Constant | Quadratic square of `Packet Length Std` (r > 0.98), redundant scale. |

## 3. Retained Sparse Protocol Flags

As instructed, rare protocol flags were **not removed**, as rare protocol behaviors are critical signatures of scan and flood attacks:
- `Fwd URG Flags` (Retained; urgent pointer anomaly)
- `CWE Flag Count` (Retained; congestion window reduced anomaly)
- `ECE Flag Count` (Retained; ECN-Echo flag)
- `RST Flag Count` (Retained; abnormal connection teardown)

## 4. Destination Port Service Categorization

To prevent the Isolation Forest model from shortcut-learning specific port numbers, `Destination Port` is preserved as a raw field for filtering/analysis, and a derived categorical feature `destination_port_group` was created:

| Service Category | Port Numbers / Ranges | Semantic Justification |
| :--- | :--- | :--- |
| **Web** | 80, 443, 8080, 8443, 8000, 8888, 5000 | Standard HTTP/HTTPS and common web application services |
| **SSH** | 22 | Secure shell remote access |
| **FTP** | 20, 21, 989, 990 | File transfer protocol control and data channels |
| **DNS** | 53, 5353, 5355 | Domain name system, mDNS, and LLMNR |
| **Mail** | 25, 110, 143, 465, 587, 993, 995 | SMTP, POP3, IMAP, and secure email submission |
| **Ephemeral/High Port** | 49152 – 65535 | Dynamic client ports assigned by OS networking stack |
| **Other/Common** | All other registered / system ports | Common enterprise services (SMB, RDP, Kerberos, LDAP, NTP, etc.) |

## 5. Domain-Grounded Negative Artifact Corrections

Rather than blindly clipping all columns, each negative artifact was addressed according to its physical protocol root cause:

| Affected Feature(s) | Negative Rows | Minimum Value | Treatment Applied | Domain Justification |
| :--- | :---: | :---: | :--- | :--- |
| `Flow Duration` | 113 | -13.0 μs | Corrected to `max(abs(duration), 1.0)` | Two-packet flows (1 fwd, 1 bwd) where sniffer interface timestamp jitter recorded response packet 1–13 μs before request. True duration is near-instantaneous. |
| `Flow Bytes/s`, `Flow Packets/s` | 113 | -2.61e+08 | Recalculated from corrected positive `Flow Duration` | Negative rates were direct algebraic derivatives of negative duration ($\Delta t < 0$). Correcting duration restored positive rates. |
| `Flow IAT Min/Mean/Max`, `Fwd IAT Min` | 2,887 | -14.0 μs | Clipped lower bound to `0.0` | Small microsecond packet capture buffer jitter. Physically, packet inter-arrival time cannot be negative. |
| `Fwd Header Length` | 35 | -3.22e+10 | Replaced with `Total Fwd Packets * 20` | CICFlowMeter 32-bit signed integer underflow when parsing corrupted TCP option offsets. Restored minimum standard TCP header (20 bytes/pkt). |
| `Bwd Header Length` | 22 | -1.07e+09 | Replaced with `Total Backward Packets * 20` | Same 32-bit integer underflow on backward packets. Restored minimum standard TCP header (20 bytes/pkt). |
| `min_seg_size_forward` | 35 | -5.37e+08 | Replaced with `20` | 32-bit integer underflow. Restored standard minimum TCP segment size (20 bytes). |

## 6. Sentinel Value Representation

For `Init_Win_bytes_forward` and `Init_Win_bytes_backward`, `-1` is a documented sentinel indicating non-TCP flows (UDP/ICMP) or flows missing the handshake SYN / SYN-ACK. These rows were not deleted; instead, they were decomposed into two complementary features:

| Original Feature | Sentinel Rows (-1) | Engineered Representation | Semantic Meaning |
| :--- | :---: | :--- | :--- |
| `Init_Win_bytes_forward` | 951,492 (37.0%) | `has_init_win_forward` (binary 0/1)<br>`init_win_bytes_forward_clean` (log1p) | Flag indicates whether forward TCP SYN was present. Cleaned numerical feature tracks window capacity without negative distortion. |
| `Init_Win_bytes_backward` | 1,264,134 (49.1%) | `has_init_win_backward` (binary 0/1)<br>`init_win_bytes_backward_clean` (log1p) | Flag indicates whether backward TCP SYN-ACK was captured. Cleaned numerical feature tracks receiver window size. |

## 7. Multi-Signal Feature Grouping (5 Behavioral Dimensions)

The **63 modeling features** are partitioned into 5 orthogonal behavioral dimensions for the multi-signal thresholding architecture:

### 7.1 Volume & Size (19 features)
| # | Feature Name | Transform Applied | Role in Anomaly Detection |
| :---: | :--- | :---: | :--- |
| 1 | `Total Fwd Packets` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 2 | `Total Backward Packets` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 3 | `Total Length of Fwd Packets` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 4 | `Total Length of Bwd Packets` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 5 | `Fwd Packet Length Max` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 6 | `Fwd Packet Length Min` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 7 | `Fwd Packet Length Mean` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 8 | `Fwd Packet Length Std` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 9 | `Bwd Packet Length Max` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 10 | `Bwd Packet Length Min` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 11 | `Bwd Packet Length Mean` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 12 | `Bwd Packet Length Std` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 13 | `Min Packet Length` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 14 | `Max Packet Length` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 15 | `Packet Length Mean` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 16 | `Packet Length Std` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 17 | `Average Packet Size` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 18 | `act_data_pkt_fwd` | `log1p(x)` | Captures payload depth, asymmetric data transfer, and packet size distribution. |
| 19 | `min_seg_size_forward` | `Linear / Binary` | Captures payload depth, asymmetric data transfer, and packet size distribution. |

### 7.2 Rate & Velocity (4 features)
| # | Feature Name | Transform Applied | Role in Anomaly Detection |
| :---: | :--- | :---: | :--- |
| 1 | `Flow Bytes/s` | `log1p(x)` | Detects volumetric flooding, burst rate spikes, and high-frequency DoS. |
| 2 | `Flow Packets/s` | `log1p(x)` | Detects volumetric flooding, burst rate spikes, and high-frequency DoS. |
| 3 | `Fwd Packets/s` | `log1p(x)` | Detects volumetric flooding, burst rate spikes, and high-frequency DoS. |
| 4 | `Bwd Packets/s` | `log1p(x)` | Detects volumetric flooding, burst rate spikes, and high-frequency DoS. |

### 7.3 Temporal / IAT (15 features)
| # | Feature Name | Transform Applied | Role in Anomaly Detection |
| :---: | :--- | :---: | :--- |
| 1 | `Flow Duration` | `log1p(x)` | Identifies automated script pacing, fast scanning, and timing jitter. |
| 2 | `Flow IAT Mean` | `log1p(x)` | Identifies automated script pacing, fast scanning, and timing jitter. |
| 3 | `Flow IAT Std` | `log1p(x)` | Identifies automated script pacing, fast scanning, and timing jitter. |
| 4 | `Flow IAT Max` | `log1p(x)` | Identifies automated script pacing, fast scanning, and timing jitter. |
| 5 | `Flow IAT Min` | `log1p(x)` | Identifies automated script pacing, fast scanning, and timing jitter. |
| 6 | `Fwd IAT Total` | `log1p(x)` | Identifies automated script pacing, fast scanning, and timing jitter. |
| 7 | `Fwd IAT Mean` | `log1p(x)` | Identifies automated script pacing, fast scanning, and timing jitter. |
| 8 | `Fwd IAT Std` | `log1p(x)` | Identifies automated script pacing, fast scanning, and timing jitter. |
| 9 | `Fwd IAT Max` | `log1p(x)` | Identifies automated script pacing, fast scanning, and timing jitter. |
| 10 | `Fwd IAT Min` | `log1p(x)` | Identifies automated script pacing, fast scanning, and timing jitter. |
| 11 | `Bwd IAT Total` | `log1p(x)` | Identifies automated script pacing, fast scanning, and timing jitter. |
| 12 | `Bwd IAT Mean` | `log1p(x)` | Identifies automated script pacing, fast scanning, and timing jitter. |
| 13 | `Bwd IAT Std` | `log1p(x)` | Identifies automated script pacing, fast scanning, and timing jitter. |
| 14 | `Bwd IAT Max` | `log1p(x)` | Identifies automated script pacing, fast scanning, and timing jitter. |
| 15 | `Bwd IAT Min` | `log1p(x)` | Identifies automated script pacing, fast scanning, and timing jitter. |

### 7.4 TCP Protocol / Flags (17 features)
| # | Feature Name | Transform Applied | Role in Anomaly Detection |
| :---: | :--- | :---: | :--- |
| 1 | `Fwd PSH Flags` | `Linear / Binary` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |
| 2 | `Fwd URG Flags` | `Linear / Binary` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |
| 3 | `FIN Flag Count` | `Linear / Binary` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |
| 4 | `SYN Flag Count` | `Linear / Binary` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |
| 5 | `RST Flag Count` | `Linear / Binary` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |
| 6 | `PSH Flag Count` | `Linear / Binary` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |
| 7 | `ACK Flag Count` | `Linear / Binary` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |
| 8 | `URG Flag Count` | `Linear / Binary` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |
| 9 | `CWE Flag Count` | `Linear / Binary` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |
| 10 | `ECE Flag Count` | `Linear / Binary` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |
| 11 | `Down/Up Ratio` | `Linear / Binary` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |
| 12 | `Fwd Header Length` | `log1p(x)` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |
| 13 | `Bwd Header Length` | `log1p(x)` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |
| 14 | `has_init_win_forward` | `Linear / Binary` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |
| 15 | `init_win_bytes_forward_clean` | `log1p(x)` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |
| 16 | `has_init_win_backward` | `Linear / Binary` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |
| 17 | `init_win_bytes_backward_clean` | `log1p(x)` | Detects protocol handshake discipline, port scans, SYN floods, and abnormal resets. |

### 7.5 Activity & Silence (8 features)
| # | Feature Name | Transform Applied | Role in Anomaly Detection |
| :---: | :--- | :---: | :--- |
| 1 | `Active Mean` | `log1p(x)` | Captures periodic command-and-control beaconing, Slowloris, and tunnel persistence. |
| 2 | `Active Std` | `log1p(x)` | Captures periodic command-and-control beaconing, Slowloris, and tunnel persistence. |
| 3 | `Active Max` | `log1p(x)` | Captures periodic command-and-control beaconing, Slowloris, and tunnel persistence. |
| 4 | `Active Min` | `log1p(x)` | Captures periodic command-and-control beaconing, Slowloris, and tunnel persistence. |
| 5 | `Idle Mean` | `log1p(x)` | Captures periodic command-and-control beaconing, Slowloris, and tunnel persistence. |
| 6 | `Idle Std` | `log1p(x)` | Captures periodic command-and-control beaconing, Slowloris, and tunnel persistence. |
| 7 | `Idle Max` | `log1p(x)` | Captures periodic command-and-control beaconing, Slowloris, and tunnel persistence. |
| 8 | `Idle Min` | `log1p(x)` | Captures periodic command-and-control beaconing, Slowloris, and tunnel persistence. |

## 8. Target Labeling

Two ground-truth columns are maintained:
1. `Label`: Original multiclass ground-truth string (`BENIGN`, `DDoS`, `PortScan`, `Bot`, `Infiltration`, `Web Attack`, etc.) for fine-grained per-attack performance evaluation.
2. `is_anomaly`: Binary target (`0` = BENIGN [2,146,899 flows], `1` = Attack [425,741 flows]) for ROC-AUC, Precision, and Recall scoring.

> **Strict Guardrail**: Neither `Label` nor `is_anomaly` will be supplied as input features to Isolation Forest.

## 9. Verification & Data Quality Audit

| Quality Check | Target | Result | Status |
| :--- | :---: | :---: | :---: |
| Total Processed Flows | 2,572,640 | 2,572,640 | **PASSED** (100% rows preserved) |
| Missing Values (NaN) | 0 | 0 | **PASSED** |
| Infinite Values (±Inf) | 0 | 0 | **PASSED** |
| Physically Impossible Negative Values | 0 | 0 | **PASSED** |
| Data Shuffling | None | Row order strictly preserved | **PASSED** |
| Storage Format | Parquet | Snappy compressed (Spark / HDFS ready) | **PASSED** |

