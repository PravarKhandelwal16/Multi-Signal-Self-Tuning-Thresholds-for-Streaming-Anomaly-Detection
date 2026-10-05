# DATA PREPROCESSING AND FEATURE ENGINEERING REPORT

**Dataset**: CSE-CIC-IDS2018 Network Traffic Dataset  
**Domain**: Network Intrusion Detection & Traffic Characterization  
**Document Type**: Technical Preprocessing Specification & Academic Review Report  
**Status**: Completed  

---

## TABLE OF CONTENTS

1. [Dataset Overview](#1-dataset-overview)
2. [Preprocessing Objective](#2-preprocessing-objective)
3. [Data Cleaning](#3-data-cleaning)
4. [Duplicate and Redundant Feature Removal](#4-duplicate-and-redundant-feature-removal)
5. [Invalid Value Analysis and Correction](#5-invalid-value-analysis-and-correction)
6. [Sentinel Value Handling](#6-sentinel-value-handling)
7. [Destination Port Feature Engineering](#7-destination-port-feature-engineering)
8. [Numerical Feature Transformation](#8-numerical-feature-transformation)
9. [Feature Grouping](#9-feature-grouping)
10. [Label Preparation](#10-label-preparation)
11. [Final Dataset Summary](#11-final-dataset-summary)
12. [Before vs. After Comparison](#12-before-vs-after-comparison)
13. [Data Quality Validation](#13-data-quality-validation)
14. [Preprocessing Pipeline Visual](#14-preprocessing-pipeline-visual)

---

## 1. DATASET OVERVIEW

The CSE-CIC-IDS2018 dataset is an industry-standard network security benchmark developed by the Canadian Institute for Cybersecurity (CIC) and the Communications Security Establishment (CSE). The dataset comprises bidirectional network traffic flows captured across an enterprise network infrastructure subjected to simulated attacks alongside benign background activities.

A network flow is defined as a sequence of packets exchanged between two communicating network endpoints identified by a 5-tuple specification (Source IP, Destination IP, Source Port, Destination Port, and Transport Protocol) within a bounded temporal window.

Table 1 summarizes the baseline dimensional characteristics of the dataset at ingestion and upon completion of preprocessing.

#### Table 1: Dataset Macro Parameters
| Parameter | Value |
| :--- | ---: |
| Dataset | CSE-CIC-IDS2018 |
| Number of input files | 8 |
| Initial records (flows) | 2,830,743 |
| Initial numerical features | 78 |
| Final records (flows) | 2,572,640 |
| Final modeling features | 63 |
| Final total columns | 67 |

---

## 2. PREPROCESSING OBJECTIVE

The primary objective of the preprocessing pipeline was to establish a rigorous, mathematically valid, and noise-free feature representation of network flow observations. Specifically, preprocessing operations were executed to:

* Enhance underlying data quality by isolating and excising defective measurement records.
* Eliminate uninformative zero-variance features and collinear redundant dimensions.
* Rectify physically impossible negative values resulting from packet timestamp jitter and arithmetic register underflow.
* Re-encode special sentinel values into mathematically sound numerical indicators.
* Stabilize heavy right-skewed metric distributions using variance-stabilizing transformations.
* Derive functional categorical features from transport-layer endpoint parameters.
* Deliver a validated, non-null, model-ready feature store formatted for high-throughput computation.

---

## 3. DATA CLEANING

Initial inspection of the raw CSV records identified systematic defects stemming from network packet sniffer anomalies and software serialization issues.

Flow records with a reported duration of zero (`Flow Duration == 0`) represented degenerate captures where transmission timing could not be resolved. These records constituted the exclusive origin of all missing (`NaN`) and undefined division-by-zero (`+Infinity`, `-Infinity`) values in derived rate metrics (`Flow Bytes/s`, `Flow Packets/s`). Additionally, multi-sensor network taps generated duplicate flow logs across overlapping capture windows.

Table 2 details the cleaning interventions and the respective record counts affected.

#### Table 2: Data Cleaning Interventions
| Cleaning Operation | Records Affected | Action Taken |
| :--- | ---: | :--- |
| Zero-duration / invalid rows | 2,867 | Removed |
| Duplicate rows | 255,236 | Removed |
| NaN values | Identified during cleaning | Resolved (via zero-duration removal) |
| Infinite values | Identified during cleaning | Resolved (via zero-duration removal) |
| Label formatting issue | Identified in Web Attacks | Corrected (Unicode `\ufffd` to en-dash `–`) |

```
================================================================================
RECORD FILTERING WATERFALL
================================================================================

   INITIAL RECORDS
      2,830,743
          │
          ▼
   Invalid Rows Removed (Zero Duration / NaN / Inf)
        - 2,867
          │
          ▼
   Exact Duplicate Rows Removed
      - 255,236
          │
          ▼
   FINAL CLEAN RECORDS
      2,572,640  (90.88% of original corpus preserved)
================================================================================
```

---

## 4. DUPLICATE AND REDUNDANT FEATURE REMOVAL

Features that exhibit zero empirical variance across all observations or represent exact duplicate measurements of other columns contribute zero entropy and needlessly expand feature dimensionality. 

Sixteen features were formally removed from the candidate feature set: eight constant features and eight duplicate/redundant features.

#### Table 3: Constant Features Removed (Zero Variance)
| Feature | Reason for Removal |
| :--- | :--- |
| `Bwd PSH Flags` | Constant value (0.0 across all 2,572,640 records) |
| `Bwd URG Flags` | Constant value (0.0 across all 2,572,640 records) |
| `Fwd Avg Bytes/Bulk` | Constant value (0.0 across all 2,572,640 records) |
| `Fwd Avg Packets/Bulk` | Constant value (0.0 across all 2,572,640 records) |
| `Fwd Avg Bulk Rate` | Constant value (0.0 across all 2,572,640 records) |
| `Bwd Avg Bytes/Bulk` | Constant value (0.0 across all 2,572,640 records) |
| `Bwd Avg Packets/Bulk` | Constant value (0.0 across all 2,572,640 records) |
| `Bwd Avg Bulk Rate` | Constant value (0.0 across all 2,572,640 records) |

#### Table 4: Collinear and Redundant Features Removed
| Feature | Redundant With / Reason |
| :--- | :--- |
| `Fwd Header Length.1` | Exact byte duplicate of `Fwd Header Length` ($r = 1.0000$) |
| `Subflow Fwd Packets` | Identical to `Total Fwd Packets` in single-flow export ($r = 1.0000$) |
| `Subflow Fwd Bytes` | Identical to `Total Length of Fwd Packets` ($r = 1.0000$) |
| `Subflow Bwd Packets` | Identical to `Total Backward Packets` in single-flow export ($r = 1.0000$) |
| `Subflow Bwd Bytes` | Identical to `Total Length of Bwd Packets` ($r = 1.0000$) |
| `Avg Fwd Segment Size` | Identical to `Fwd Packet Length Mean` ($r = 1.0000$) |
| `Avg Bwd Segment Size` | Identical to `Bwd Packet Length Mean` ($r = 1.0000$) |
| `Packet Length Variance` | Collinear quadratic square of `Packet Length Std` ($r > 0.9800$) |

**Total Features Removed = 16**

```
┌────────────────────────────────────────────────────────┐
│ 78 Original Numerical Features                         │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ 16 Redundant / Constant Features Removed               │
│ • 8 Constant features (zero variance)                  │
│ • 8 Collinear duplicates (r = 1.0000)                  │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Retained Core Numerical Feature Space                  │
└────────────────────────────────────────────────────────┘
```

Sparse protocol flags (`Fwd URG Flags`, `CWE Flag Count`, `ECE Flag Count`, and `RST Flag Count`) were explicitly preserved, as rare protocol flag assertations characterize low-volume stealth scan activities.

---

## 5. INVALID VALUE ANALYSIS AND CORRECTION

Physical network attributes (elapsed duration, inter-arrival time, packet length, and transmission rate) are non-negative by definition. The raw data contained negative values in eight features, attributable to two documented technical causes:

1. **Microsecond Sniffer Clock Skew**: In bidirectional flows comprising two packets, independent capture network interfaces recorded the response packet slightly earlier than the forward packet, resulting in small negative duration and inter-arrival calculations ($\Delta t \in [-14\,\mu\text{s}, -1\,\mu\text{s}]$).
2. **Java Integer Underflow**: The feature generation software (CICFlowMeter) utilized 32-bit signed integers when parsing corrupted TCP option offsets, producing negative underflow values (e.g., $-3.22 \times 10^{10}$).

Corrections were applied based on the underlying protocol semantics rather than arbitrary heuristic clipping.

#### Table 5: Negative Value Remediation
| Feature | Issue Identified | Negative Rows | Minimum Value | Correction Applied |
| :--- | :--- | ---:| ---:| :--- |
| `Flow Duration` | Negative duration values | 113 | $-13.0\,\mu\text{s}$ | Corrected to absolute physical duration: $\max(\|\text{duration}\|, 1.0\,\mu\text{s})$ |
| `Flow Bytes/s` | Negative rate values | 84 | $-2.61 \times 10^8$ | Recalculated using corrected positive `Flow Duration` |
| `Flow Packets/s` | Negative rate values | 113 | $-2.00 \times 10^6$ | Recalculated using corrected positive `Flow Duration` |
| `Flow IAT Mean` | Negative IAT values | 113 | $-13.0\,\mu\text{s}$ | Lower bound set to $0.0$ (measurement jitter correction) |
| `Flow IAT Max` | Negative IAT values | 113 | $-13.0\,\mu\text{s}$ | Lower bound set to $0.0$ (measurement jitter correction) |
| `Flow IAT Min` | Negative IAT values | 2,887 | $-14.0\,\mu\text{s}$ | Lower bound set to $0.0$ (measurement jitter correction) |
| `Fwd IAT Min` | Negative IAT values | 17 | $-12.0\,\mu\text{s}$ | Lower bound set to $0.0$ (measurement jitter correction) |
| `Fwd Header Length` | Unrealistic negative values | 35 | $-3.22 \times 10^{10}$ | Reconstructed: $\text{Total Fwd Packets} \times 20\text{ bytes}$ (standard TCP min) |
| `Bwd Header Length` | Unrealistic negative values | 22 | $-1.07 \times 10^9$ | Reconstructed: $\text{Total Backward Packets} \times 20\text{ bytes}$ (standard TCP min) |
| `min_seg_size_forward` | Unrealistic negative values | 35 | $-5.37 \times 10^8$ | Replaced with standard protocol minimum ($20\text{ bytes}$) |

```
┌────────────────────────────────────────────────────────┐
│ BEFORE CORRECTION                                      │
│ Negative values present across 8 network features      │
│ (Range: -1.0 us to -3.22e+10 integer underflow)        │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ DOMAIN-BASED PROTOCOL CORRECTION                       │
│ • Duration resolved via physical absolute elapsed time │
│ • Rates recalculated from corrected durations          │
│ • Jitter bounded to zero minimum                       │
│ • Corrupted headers reconstructed from packet counts   │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ AFTER CORRECTION                                       │
│ 0 physically impossible negative values remaining      │
└────────────────────────────────────────────────────────┘
```

---

## 6. SENTINEL VALUE HANDLING

In TCP flow analysis, initial window advertisement bytes indicate socket buffer allocation negotiated during connection handshakes. The raw features `Init_Win_bytes_forward` and `Init_Win_bytes_backward` exhibited values of `-1` across 951,492 and 1,264,134 flows, respectively.

The value `-1` is a software sentinel utilized by CICFlowMeter to signify that initial window information was not applicable (such as in connectionless UDP or ICMP flows) or that the three-way handshake SYN/SYN-ACK exchange occurred outside the capture boundary.

Treating `-1` as continuous numerical data introduces severe artificial negative bias. Deleting affected rows would excise 49.1% of the valid dataset corpus. Consequently, each sentinel column was decoupled into two complementary attributes:

1. A binary indicator signaling handshake presence.
2. A non-negative numerical magnitude preserving window size information.

#### Table 6: Sentinel Decomposition Specification
| Original Feature | Sentinel Rows ($-1$) | Derived Features Created | Description |
| :--- | ---:| :--- | :--- |
| `Init_Win_bytes_forward` | 951,492 | `has_init_win_forward`<br>`init_win_bytes_forward_clean` | Binary flag ($1 = \text{TCP SYN observed}, 0 = \text{Absent/UDP}$)<br>Continuous window bytes ($\ge 0$, sentinel clamped to 0) |
| `Init_Win_bytes_backward` | 1,264,134 | `has_init_win_backward`<br>`init_win_bytes_backward_clean` | Binary flag ($1 = \text{TCP SYN-ACK observed}, 0 = \text{Absent}$)<br>Continuous window bytes ($\ge 0$, sentinel clamped to 0) |

```
   Original Feature (Contains -1 Sentinel)
                  │
                  ▼
   Identify -1 Sentinel Observations
                  │
                  ▼
        ┌───────────────────┴───────────────────┐
        ▼                                       ▼
   Presence Indicator                 Clean Numerical Value
   (has_init_win_*)                  (init_win_bytes_*_clean)
   Binary: 0 or 1                    Clamped to >= 0
        └───────────────────┬───────────────────┘
                            │
                            ▼
              Final Feature Representation
```

---

## 7. DESTINATION PORT FEATURE ENGINEERING

Raw port numbers represent categorical network service identifiers rather than scalar quantities. Using continuous numerical ports can lead models to artificially memorize specific lab host assignments (for example, identifying port 21 exclusively with FTP brute-force scripts).

To preserve application context while avoiding artificial scalar assumptions, `Destination Port` was retained as an integer reference, and a derived categorical attribute, `destination_port_group`, was constructed according to standard IANA service allocations.

#### Table 7: Destination Port Group Mapping
| Service Group | Port Range / Identifiers | Service Domain |
| :--- | :--- | :--- |
| `Web` | 80, 443, 8080, 8443, 8000, 8888, 5000 | Hypertext Transfer Protocols (HTTP, HTTPS, Web Proxies) |
| `SSH` | 22 | Secure Shell Remote Access |
| `FTP` | 20, 21, 989, 990 | File Transfer Protocol (Control and Data Channels) |
| `DNS` | 53, 5353, 5355 | Domain Name Services, Multicast DNS, LLMNR |
| `Mail` | 25, 110, 143, 465, 587, 993, 995 | Email Routing and Retrieval (SMTP, POP3, IMAP, SMTPS) |
| `Ephemeral/High Port` | 49152 – 65535 | Dynamic client ports allocated by host operating systems |
| `Other/Common` | All remaining assigned ports | Enterprise infrastructure services (SMB, RDP, Kerberos, LDAP, NTP) |

Both `Destination Port` (raw numeric) and `destination_port_group` (service group) are retained in the final dataset schema.

---

## 8. NUMERICAL FEATURE TRANSFORMATION

The log1p transformation was applied to highly skewed non-negative numerical features to reduce the influence of extremely large values while preserving zero-valued observations.

$$\log1p(x) = \ln(1 + x)$$

In empirical network traffic, metrics such as bytes transferred, packet counts, and microsecond timings span multiple orders of magnitude (e.g., from 0 to $6.55 \times 10^8$ bytes). The natural logarithm mapping contracts the dynamic range of continuous distributions, mitigating heavy right-skew without distorting zero-magnitude observations ($\log1p(0) = 0$).

Discrete binary flags, indicators, and bounded ratios were maintained in their native linear representation.

#### Table 8: Feature Transformation Strategy
| Feature Group | Representative Features | Transformation Applied |
| :--- | :--- | :--- |
| Volume & Size | `Total Fwd Packets`, `Total Length of Fwd Packets`, `Packet Length Mean` | $\log1p$ |
| Rate & Velocity | `Flow Bytes/s`, `Flow Packets/s`, `Fwd Packets/s`, `Bwd Packets/s` | $\log1p$ |
| Temporal / IAT | `Flow Duration`, `Flow IAT Mean`, `Fwd IAT Mean`, `Bwd IAT Total` | $\log1p$ |
| Activity & Silence | `Active Mean`, `Active Max`, `Idle Mean`, `Idle Max` | $\log1p$ |
| Protocol / Flags | `FIN Flag Count`, `SYN Flag Count`, `Down/Up Ratio`, `has_init_win_forward` | Linear / Binary (Native) |

---

## 9. FEATURE GROUPING

To facilitate multi-dimensional behavioral traffic profiling, the 63 retained modeling features were systematically mapped into five orthogonal behavioral groups.

```
┌────────────────────────────────────────────────────────┐
│                   Volume & Size                        │
│                (19 Feature Metrics)                    │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│                  Rate & Velocity                       │
│                 (4 Feature Metrics)                    │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│                   Temporal / IAT                       │
│                (15 Feature Metrics)                    │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│                TCP Protocol / Flags                    │
│                (17 Feature Metrics)                    │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│                 Activity & Silence                     │
│                 (8 Feature Metrics)                    │
└────────────────────────────────────────────────────────┘
```

#### Table 9: Behavioral Feature Groups
| Feature Group | Number of Features | Description |
| :--- | ---:| :--- |
| **Volume & Size** | 19 | Flow payload capacity, asymmetric byte volumes, packet size distributions |
| **Rate & Velocity** | 4 | Instantaneous data throughput and packet generation frequency |
| **Temporal / IAT** | 15 | Flow duration, packet pacing, and inter-arrival arrival timing dispersion |
| **TCP Protocol / Flags** | 17 | Connection handshake discipline, TCP flag frequencies, and header overhead |
| **Activity & Silence** | 8 | Periodic transmission burst durations and dormant idle intervals |

**Total Modeling Features = 63**

---

## 10. LABEL PREPARATION

The processed dataset contains two separate ground-truth target columns to support both multiclass attack categorization and binary anomaly verification.

#### Table 10: Ground Truth Target Attributes
| Column | Type | Class Distribution | Description |
| :--- | :---: | :--- | :--- |
| `Label` | Categorical String | 15 distinct classes (BENIGN, DDoS, PortScan, DoS, etc.) | Original fine-grained attack taxonomy |
| `is_anomaly` | Binary Integer | $\text{BENIGN } (0): 2,146,899 \text{ flows } (83.45\%)$<br>$\text{ATTACK } (1): \phantom{0}425,741 \text{ flows } (16.55\%)$ | Binary classification ground truth |

Neither `Label` nor `is_anomaly` constitutes an input feature; both serve strictly as evaluation benchmarks.

---

## 11. FINAL DATASET SUMMARY

Preprocessing operations yielded an optimized, mathematically validated dataset saved in Apache Parquet format utilizing Snappy block compression.

#### Table 11: Final Processed Dataset Specifications
| Metric | Final Result |
| :--- | ---:|
| Total flows | 2,572,640 |
| Modeling features | 63 |
| Derived / engineered features | 5 |
| Context columns (`Destination Port`, `destination_port_group`) | 2 |
| Target evaluation labels (`Label`, `is_anomaly`) | 2 |
| Total columns in schema | 67 |
| Missing values (NaN) | 0 |
| Infinite values ($\pm\infty$) | 0 |
| Physically impossible negative values | 0 |
| Duplicate rows | 0 |
| Row order | Preserved (Chronological) |
| Output format | Apache Parquet |
| Compression codec | Snappy |

```
================================================================================
PREPROCESSING AND FEATURE-ENGINEERING FLOW
================================================================================

   RAW DATASET
   2,830,743 records
   78 numerical features
          │
          ▼
   ┌──────────────────────────────────────────────┐
   │ DATA CLEANING                                │
   │ • 2,867 zero-duration flows removed          │
   │ • 255,236 duplicate records eliminated       │
   │ • 0 missing (NaN) and 0 infinite values      │
   └──────────────────────┬───────────────────────┘
                          │
                          ▼
   ┌──────────────────────────────────────────────┐
   │ FEATURE ENGINEERING                          │
   │ • 16 redundant & constant features removed   │
   │ • 8 negative value artifacts corrected      │
   │ • Sentinel window values (-1) decomposed     │
   │ • Skewed metrics stabilized via log1p        │
   │ • Destination port categorized into services │
   └──────────────────────┬───────────────────────┘
                          │
                          ▼
   FINAL MODEL-READY DATASET
   2,572,640 records
   63 modeling features
   67 total columns
   0 NaN / 0 Inf / 0 Negatives
   Snappy Parquet format
================================================================================
```

---

## 12. BEFORE VS. AFTER COMPARISON

Table 12 presents a direct comparison of dataset characteristics before and after preprocessing.

#### Table 12: Preprocessing Transformation Audit
| Parameter | Before Preprocessing | After Preprocessing |
| :--- | ---:| ---:|
| Total records (flows) | 2,830,743 | 2,572,640 |
| Numerical candidate features | 78 | 63 modeling features |
| Duplicate records | 255,236 | 0 |
| Missing values (NaN) | Present | 0 |
| Infinite values ($\pm\infty$) | Present | 0 |
| Physically impossible negative values | Present | 0 |
| Sentinel $-1$ distortion | Present in 2 columns | 0 (Re-encoded) |
| Extreme right-skew | Unbounded | Normalized via $\log1p$ |
| Storage format | Multiple uncompressed CSVs | Snappy Parquet |

---

## 13. DATA QUALITY VALIDATION

Automated validation routines executed against the final feature store verified compliance across all quality benchmarks.

#### Table 13: Data Quality Compliance Audit
| Quality Check | Evaluation Criteria | Result Observed | Status |
| :--- | :--- | ---:| :---: |
| Record Preservation | Correct extraction of valid non-duplicate rows | 2,572,640 | **PASS** |
| Missing Values | Null / NaN instances across all columns | 0 | **PASS** |
| Infinite Values | Undefined $+Inf / -Inf$ arithmetic instances | 0 | **PASS** |
| Impossible Negatives | Physical metrics $\ge 0$ | 0 | **PASS** |
| Duplicate Redundancy | Exact row-level duplicates | 0 | **PASS** |
| Sequence Order | Temporal chronological stability | Preserved | **PASS** |
| Storage Format | Validated Snappy-compressed Parquet | Confirmed | **PASS** |

---

## 14. PREPROCESSING PIPELINE VISUAL

Figure 1 illustrates the sequential flow of all preprocessing and feature engineering operations applied to the CSE-CIC-IDS2018 dataset.

```
                  CSE-CIC-IDS2018 Raw Files
                              │
                              ▼
                        Data Cleaning
             (Zero duration, NaN, and Inf excised)
                              │
                              ▼
                      Duplicate Removal
             (255,236 duplicate flow records dropped)
                              │
                              ▼
                      Feature Analysis
         (Variance, correlation, and distribution audit)
                              │
                              ▼
                     Redundancy Removal
             (16 constant and collinear features excised)
                              │
                              ▼
                 Invalid Value Correction
        (Negative timings and integer underflows rectified)
                              │
                              ▼
                 Sentinel Value Handling
         (Window size -1 sentinels decoupled to indicators)
                              │
                              ▼
                   Feature Transformation
            (Log1p scaling applied to right-skewed metrics)
                              │
                              ▼
                    Feature Engineering
         (Destination port grouped into service categories)
                              │
                              ▼
                     Feature Grouping
            (63 modeling features mapped into 5 signals)
                              │
                              ▼
                  Final Clean Dataset Store
         (2,572,640 flows, 67 columns, Snappy Parquet)
```
*Figure 1: End-to-end data preprocessing and feature engineering pipeline.*
