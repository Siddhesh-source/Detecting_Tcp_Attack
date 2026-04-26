"""
Diagnostic: compare dataset columns vs FEATURE_COLS used by the model.
Run from the backend directory:  python analyze_dataset.py
Results show what is mapped, what is derived, and what is zeroed out.
"""
import pandas as pd
import numpy as np

TRAIN_CSV = r"D:\CN\data\train.csv"
TEST_CSV  = r"D:\CN\data\test.csv"

# Must stay in sync with ml_model.py
FEATURE_COLS = [
    "duration",
    "total_packets",
    "total_bytes",
    "mean_pkt_size",
    "std_pkt_size",
    "pkt_len_std",
    "packets_per_sec",
    "bytes_per_sec",
    "mean_iat",
    "std_iat",
    "fwd_iat_total",
    "bwd_iat_total",
    "bwd_iat_mean",
    "bwd_iat_std",
    "burst_count",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "retransmit_count",
    "avg_window_size",
    "fwd_bwd_ratio",
    "active_mean",
    "idle_mean",
]

CIC_TO_OUR = {
    "Destination Port":              "dst_port",
    "Flow Duration":                 "duration",
    "Total Fwd Packets":             "fwd_packets",
    "Total Backward Packets":        "bwd_packets",
    "Total Length of Fwd Packets":   "fwd_bytes",
    "Total Length of Bwd Packets":   "bwd_bytes",
    "Average Packet Size":           "mean_pkt_size",
    "Fwd Packet Length Std":         "std_pkt_size",
    "Packet Length Std":             "pkt_len_std",
    "Flow Bytes/s":                  "bytes_per_sec",
    "Flow Packets/s":                "packets_per_sec",
    "Flow IAT Mean":                 "mean_iat",
    "Flow IAT Std":                  "std_iat",
    "Flow IAT Max":                  "max_iat",
    "Flow IAT Min":                  "min_iat",
    "Fwd IAT Total":                 "fwd_iat_total",
    "Fwd IAT Mean":                  "fwd_iat_mean",
    "Fwd IAT Std":                   "fwd_iat_std",
    "Fwd IAT Max":                   "fwd_iat_max",
    "Fwd IAT Min":                   "fwd_iat_min",
    "Bwd IAT Total":                 "bwd_iat_total",
    "Bwd IAT Mean":                  "bwd_iat_mean",
    "Bwd IAT Std":                   "bwd_iat_std",
    "FIN Flag Count":                "fin_count",
    "SYN Flag Count":                "syn_count",
    "RST Flag Count":                "rst_count",
    "ACK Flag Count":                "ack_count",
    "PSH Flag Count":                "burst_count",
    "Init_Win_bytes_forward":        "avg_window_size",
    "Init_Win_bytes_backward":       "init_win_bwd",
    "Active Mean":                   "active_mean",
    "Idle Mean":                     "idle_mean",
}

DERIVED = {"total_packets", "total_bytes", "fwd_bwd_ratio"}  # computed after rename

SEP = "=" * 72

print(SEP)
print("Loading datasets...")
train = pd.read_csv(TRAIN_CSV)
test  = pd.read_csv(TEST_CSV)
print(f"Train : {len(train):>8,} rows  x  {len(train.columns)} cols")
print(f"Test  : {len(test):>8,} rows  x  {len(test.columns)} cols")

print(SEP)
print("LABEL DISTRIBUTION")
print("  Train:")
for lbl, cnt in train["Label"].value_counts().items():
    print(f"    {lbl:<20} : {cnt:>8,}  ({cnt/len(train)*100:.3f}%)")
print("  Test:")
for lbl, cnt in test["Label"].value_counts().items():
    print(f"    {lbl:<20} : {cnt:>8,}  ({cnt/len(test)*100:.3f}%)")

# Apply rename as model does
df = train.rename(columns={k: v for k, v in CIC_TO_OUR.items() if k in train.columns})
# Apply derivations as model does
if "fwd_packets" in df.columns:
    df["total_packets"] = df["fwd_packets"] + df["bwd_packets"].fillna(0)
fwd_b = df.get("fwd_bytes", pd.Series(0.0, index=df.index))
bwd_b = df.get("bwd_bytes", pd.Series(0.0, index=df.index))
df["total_bytes"] = fwd_b + bwd_b
if "fwd_packets" in df.columns:
    df["fwd_bwd_ratio"] = (df["fwd_packets"] / df["bwd_packets"].replace(0, 1)).round(4)

print()
print(SEP)
print(f"FEATURE_COLS MAPPING AUDIT  ({len(FEATURE_COLS)} features)")
print(f"  {'Feature':<22} {'Status':<10}  Source")
print("  " + "-" * 68)
n_ok = n_derived = n_zeroed = 0
for feat in FEATURE_COLS:
    cic_src = [k for k, v in CIC_TO_OUR.items() if v == feat]
    if feat in DERIVED:
        status = "DERIVED"
        note   = "computed from fwd/bwd columns after rename"
        n_derived += 1
    elif feat in df.columns:
        status = "OK"
        note   = f"CIC col: {cic_src[0]!r}" if cic_src else "present"
        n_ok += 1
    else:
        status = "ZEROED"
        note   = "no dataset column maps to this feature"
        n_zeroed += 1
    print(f"  {feat:<22} [{status:<7}]  {note}")

print()
print(f"  Summary: {n_ok} direct, {n_derived} derived, {n_zeroed} zeroed  "
      f"(out of {len(FEATURE_COLS)} total)")

print()
print(SEP)
print(f"DATASET COLUMNS NOT USED BY MODEL  ({len(train.columns)} total cols)")
used_cic = set(CIC_TO_OUR.keys())
unused   = sorted(set(train.columns) - used_cic - {"Label"})
print(f"  {len(unused)} unused columns:")
for col in unused:
    try:
        s = train[col].replace([np.inf, -np.inf], np.nan).dropna()
        print(f"  {col:<47} nunique={s.nunique():<6}  mean={s.mean():.2f}")
    except Exception:
        print(f"  {col}")

print()
print(SEP)
print("FEATURE VALUE SANITY (train, after rename + derivations)")
print(f"  {'Feature':<22} {'mean':>14} {'std':>14} {'nan':>6} {'neg':>6}")
print("  " + "-" * 68)
for feat in FEATURE_COLS:
    if feat in df.columns:
        col  = df[feat].replace([np.inf, -np.inf], np.nan)
        mean = col.mean()
        std  = col.std()
        nnan = int(col.isna().sum())
        nneg = int((col.fillna(0) < 0).sum())
        flag = "  <-- CHECK" if nneg > 0 or nnan > 100 else ""
        print(f"  {feat:<22} {mean:>14.2f} {std:>14.2f} {nnan:>6} {nneg:>6}{flag}")
    else:
        print(f"  {feat:<22} {'[zeroed]':>14}")

print()
print("Done.")
