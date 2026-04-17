"""
Load the CIC-IDS2017 Infiltration dataset from data/raw/,
clean it, and save as data/processed/cic_ids2017_processed.csv.

Source: Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
(79 columns, ~288k rows, extremely imbalanced: 288566 BENIGN / 36 Infiltration)

Cleaning steps:
  - Drop rows with NaN / Infinity in numeric columns
  - Strip whitespace from column names and Label values
  - Remove duplicate rows
  - Keep ALL columns from the original CSV (full 79-column CIC-IDS2017 schema)
  - Save cleaned dataset to data/cic_ids2017_processed.csv
  - Print class distribution after cleaning
"""

import os
import pandas as pd

# Paths
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE_FILE = os.path.join(
    PROJECT_DIR, "data", "raw",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
)
OUTPUT_FILE = os.path.join(PROJECT_DIR, "data", "processed", "cic_ids2017_processed.csv")


def main():
    print(f"Loading real CIC-IDS2017 dataset from:\n  {SOURCE_FILE}")

    df = pd.read_csv(SOURCE_FILE, low_memory=False)

    print(f"Raw rows : {len(df)}")
    print(f"Columns  : {len(df.columns)}")

    # 1. Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # 2. Strip whitespace from Label values
    df["Label"] = df["Label"].str.strip()

    # 3. Drop duplicate rows
    before = len(df)
    df = df.drop_duplicates()
    print(f"After dedup : {len(df)}  (removed {before - len(df)} duplicates)")

    # 4. Replace Infinity with NaN, then drop rows with NaN
    numeric_cols = df.select_dtypes(include="object").columns.tolist()
    for col in numeric_cols:
        if col == "Label":
            continue
        df[col] = pd.to_numeric(df[col], errors="coerce")

    before = len(df)
    df = df.replace([float("inf"), float("-inf")], pd.NA)
    df = df.dropna()
    print(f"After NaN drop: {len(df)}  (removed {before - len(df)} rows with NaN/Inf)")

    # 5. Print class distribution
    counts = df["Label"].value_counts()
    total = len(df)
    print(f"\nFinal clean dataset : {total} rows, {len(df.columns)} columns")
    print("Class distribution:")
    for label, count in counts.items():
        print(f"  {label:20s} : {count:7d}  ({count / total * 100:.2f}%)")

    # 6. Save
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"\nSaved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
