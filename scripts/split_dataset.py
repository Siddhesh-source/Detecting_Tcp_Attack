"""
Load the cleaned CIC-IDS2017 dataset (data/processed/cic_ids2017_processed.csv),
perform a stratified 80/20 train/test split by Label,
and save data/processed/train.csv and data/processed/test.csv.

Handles the extreme class imbalance (36 Infiltration out of ~252k rows)
by ensuring at least 1 sample of each class appears in both splits.
"""

import os
import pandas as pd
from sklearn.model_selection import train_test_split

# Paths
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_FILE  = os.path.join(PROJECT_DIR, "data", "processed", "cic_ids2017_processed.csv")
TRAIN_FILE  = os.path.join(PROJECT_DIR, "data", "processed", "train.csv")
TEST_FILE   = os.path.join(PROJECT_DIR, "data", "processed", "test.csv")


def main():
    print(f"Loading cleaned dataset from:\n  {INPUT_FILE}")
    df = pd.read_csv(INPUT_FILE)
    print(f"Rows: {len(df)}, Columns: {len(df.columns)}")

    # Stratified 80/20 split
    train_df, test_df = train_test_split(
        df,
        test_size=0.20,
        random_state=42,
        stratify=df["Label"],
    )

    train_df.to_csv(TRAIN_FILE, index=False)
    test_df.to_csv(TEST_FILE, index=False)

    print(f"\nTrain : {len(train_df):7d}  (saved to {TRAIN_FILE})")
    train_counts = train_df["Label"].value_counts()
    for label, count in train_counts.items():
        print(f"  {label:20s} : {count:7d}  ({count / len(train_df) * 100:.2f}%)")

    print(f"\nTest  : {len(test_df):7d}  (saved to {TEST_FILE})")
    test_counts = test_df["Label"].value_counts()
    for label, count in test_counts.items():
        print(f"  {label:20s} : {count:7d}  ({count / len(test_df) * 100:.2f}%)")


if __name__ == "__main__":
    main()
