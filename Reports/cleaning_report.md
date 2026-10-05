# Step 2 — Data Cleaning Report: CSE-CIC-IDS2018

> **Raw data was NOT modified. Cleaned files saved to `processed/` directory.**

---

## Cleaning Decisions (Based on Step 1 Findings)

### 1. NaN Values — Row Removal (not imputation)

**Column affected:** `Flow Bytes/s` only (1,358 NaN total across 8 files).

**Root cause confirmed:** `Flow Duration = 0` → CICFlowMeter divides `bytes / 0 = NaN`.
These are structurally broken flow measurements. No rate feature is meaningful for a zero-duration flow.

**Decision: Drop rows where `Flow Duration == 0`.**
Imputation was rejected because:
- The measurement is inherently undefined (not merely unobserved)
- Median/zero fill would fabricate data for corrupt records
- Affected rows represent < 0.2% of any file

### 2. Infinite Values — Replaced then Removed via Root Cause

**Columns affected:** `Flow Bytes/s` (+Inf: 1,646) and `Flow Packets/s` (+Inf: 2,730). No −Inf anywhere.

**Strategy:** Replace `+Inf` with `NaN` first, then the `Flow Duration == 0` drop handles them.
This was verified: **all** Inf values resided in zero-duration rows — zero residual Inf after the drop.

### 3. Duplicate Rows — Exact Removal, Keep First

**Total duplicates in Step 1:** 256,479 (9.06% of dataset).
These are exact matches across all 79 columns — characteristic of CICFlowMeter double-logging the same flow.
`keep='first'` preserves original row order within each file. No shuffling.

### 4. Web Attack Label Encoding Fix

**File:** `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` only.
Labels contained `\ufffd` (Unicode replacement character) — a Windows-1252 em-dash read as UTF-8.
**Fix:** Replace `\ufffd` → `–` (U+2013 en-dash).
Result: `"Web Attack – Brute Force"`, `"Web Attack – XSS"`, `"Web Attack – Sql Injection"`.

### 5. What Was NOT Changed

| Item | Decision | Reason |
|---|---|---|
| `Init_Win_bytes_backward = -1` | ✅ Preserved | Valid sentinel (no backward SYN) |
| `Fwd Header Length.1` duplicate column | ✅ Preserved | Feature selection is Step 3 |
| Normalization / scaling | ✅ Not applied | Not needed at cleaning stage |
| Train/test split | ✅ Not applied | Step 6+ |
| Row order | ✅ Preserved | No shuffling at any point |
| Attack labels | ✅ All preserved | No label-based filtering |

---

## Per-File Results

| File | Original Rows | Removed (Zero-Dur) | Removed (Dups) | **Final Rows** | % Removed |
|---|---|---|---|---|---|
| Fri-DDos | 225,745 | 34 | 2,629 | **223,082** | 1.18% |
| Fri-PortScan | 286,467 | 371 | 72,319 | **213,777** | 25.37% |
| Fri-Morning | 191,033 | 122 | 6,867 | **184,044** | 3.66% |
| Monday | 529,918 | 437 | 26,831 | **502,650** | 5.14% |
| Thu-Infiltration | 288,602 | 207 | 35,605 | **252,790** | 12.41% |
| Thu-WebAttacks | 170,366 | 135 | 6,052 | **164,179** | 3.63% |
| Tuesday | 445,909 | 264 | 24,019 | **421,626** | 5.44% |
| Wednesday | 692,703 | 1,297 | 80,914 | **610,492** | 11.87% |
| **TOTAL** | **2,830,743** | **2,867** | **255,236** | **2,572,640** | **9.12%** |

> **Note:** Duplicate counts are slightly lower than Step 1 figures because some duplicates were zero-duration rows removed first.

---

## Post-Clean Label Distribution

| Label | File | Before | After | Δ |
|---|---|---|---|---|
| BENIGN | All | 2,273,097 | 2,145,899 | −127,198 |
| DDoS | Fri-DDos | 128,027 | 128,014 | −13 |
| PortScan | Fri-PortScan | 158,930 | 90,694 | −68,236 |
| DoS Hulk | Wednesday | 231,073 | 172,846 | −58,227 |
| DoS GoldenEye | Wednesday | 10,293 | 10,286 | −7 |
| FTP-Patator | Tuesday | 7,938 | 5,931 | −2,007 |
| SSH-Patator | Tuesday | 5,897 | 3,219 | −2,678 |
| DoS slowloris | Wednesday | 5,796 | 5,385 | −411 |
| DoS Slowhttptest | Wednesday | 5,499 | 5,228 | −271 |
| Web Attack – Brute Force | Thu-WebAttacks | 1,507 | 1,470 | −37 |
| Bot | Fri-Morning | 1,966 | 1,948 | −18 |
| Web Attack – XSS | Thu-WebAttacks | 652 | 652 | 0 |
| **Infiltration** | **Thu-Infiltration** | **36** | **36** | **0** |
| **Web Attack – Sql Injection** | **Thu-WebAttacks** | **21** | **21** | **0** |
| **Heartbleed** | **Wednesday** | **11** | **11** | **0** |

> ✅ All minority attack classes fully preserved. Heartbleed (11), SQL Injection (21), and Infiltration (36) are intact.

---

## Final Quality Verification

| Metric | Result |
|---|---|
| **Original row count** | 2,830,743 |
| **Rows removed (zero-duration / NaN/Inf)** | 2,867 |
| **Rows removed (extra residual NaN/Inf)** | 0 |
| **Rows removed (exact duplicates)** | 255,236 |
| **Total rows removed** | 258,103 |
| **Final row count** | **2,572,640** |
| **Remaining NaN** | ✅ 0 |
| **Remaining +Inf** | ✅ 0 |
| **Remaining −Inf** | ✅ 0 |
| **Remaining duplicate rows** | ✅ 0 |
| **Chronological order preserved** | ✅ Yes — `keep='first'`, no shuffle |
| **Raw data modified** | ✅ No — raw CSVs untouched |
| **Label column preserved** | ✅ Yes — no label-based dropping |

---

## Output Files

All cleaned files saved to `C:\Work\Big data\processed\`:

| Cleaned File | Size |
|---|---|
| `cleaned_Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 77.98 MB |
| `cleaned_Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 63.46 MB |
| `cleaned_Friday-WorkingHours-Morning.pcap_ISCX.csv` | 59.04 MB |
| `cleaned_Monday-WorkingHours.pcap_ISCX.csv` | 175.45 MB |
| `cleaned_Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 78.99 MB |
| `cleaned_Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 52.72 MB |
| `cleaned_Tuesday-WorkingHours.pcap_ISCX.csv` | 134.96 MB |
| `cleaned_Wednesday-workingHours.pcap_ISCX.csv` | 213.54 MB |

---

## Notable Findings

1. **All NaN and Inf values were contained within `Flow Duration == 0` rows** — the Step 1 root cause hypothesis was exactly correct. Zero residual NaN/Inf after the zero-duration drop.
2. **PortScan file lost the most rows** (25.37%) — 72,319 duplicate rows, consistent with Step 1's observation that PortScan scanning produces highly repetitive flow records.
3. **Wednesday lost 11.87%** — 80,914 duplicate DoS flows, also expected from sustained DoS attack patterns.
4. **The duplicate count dropped slightly vs Step 1** (255,236 vs 256,479) because some of the "duplicates" were zero-duration rows removed earlier.
5. **Web Attack labels successfully fixed** — `Thu-WebAttacks` now uses proper en-dash (`–`) in all three attack label strings.
