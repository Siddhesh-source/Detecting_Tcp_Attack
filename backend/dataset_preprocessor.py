"""
Multi-dataset preprocessing pipeline for UNSW-NB15, CTU-13, and CICIDS2018.
Normalizes different dataset schemas to unified feature format.
"""

from __future__ import annotations

import os
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple
from pathlib import Path


class DatasetPreprocessor:
    """Unified preprocessor for multiple IDS datasets."""

    def __init__(self, data_root: str = "D:/CN"):
        self.data_root = Path(data_root)
        self.unsw_path = self.data_root / "archive"
        self.ctu_path = self.data_root / "archive (1)"
        self.cic2018_path = self.data_root / "archive (2)"

    def process_unsw_nb15(self) -> pd.DataFrame:
        """Process UNSW-NB15 dataset."""
        print("[Dataset] Processing UNSW-NB15...")
        
        train_file = self.unsw_path / "UNSW_NB15_training-set.csv"
        test_file = self.unsw_path / "UNSW_NB15_testing-set.csv"
        
        if not train_file.exists() or not test_file.exists():
            print(f"[Dataset] UNSW-NB15 files not found")
            return pd.DataFrame()
        
        df_train = pd.read_csv(train_file)
        df_test = pd.read_csv(test_file)
        df = pd.concat([df_train, df_test], ignore_index=True)
        
        # Map UNSW columns to our features
        feature_map = {
            "dur": "duration",
            "spkts": "fwd_packets",
            "dpkts": "bwd_packets",
            "sbytes": "total_bytes",
            "smeansz": "mean_pkt_size",
            "dmeansz": "bwd_pkt_mean",
            "sload": "bytes_per_sec",
            "dload": "bwd_bytes_per_sec",
            "sinpkt": "mean_iat",
            "dinpkt": "bwd_iat_mean",
            "sjit": "std_iat",
            "djit": "bwd_iat_std",
            "swin": "avg_window_size",
            "stcpb": "syn_count",
            "dtcpb": "ack_count",
            "tcprtt": "retransmit_count",
            "label": "Label",
        }
        
        df_mapped = pd.DataFrame()
        for unsw_col, our_col in feature_map.items():
            if unsw_col in df.columns:
                df_mapped[our_col] = df[unsw_col]
        
        # Derive missing features
        df_mapped["total_packets"] = df_mapped.get("fwd_packets", 0) + df_mapped.get("bwd_packets", 0)
        df_mapped["std_pkt_size"] = df.get("sstd", 0) if "sstd" in df.columns else 0
        df_mapped["packets_per_sec"] = df_mapped["total_packets"] / df_mapped["duration"].replace(0, 1)
        df_mapped["fwd_bwd_ratio"] = df_mapped["fwd_packets"] / df_mapped["bwd_packets"].replace(0, 1)
        df_mapped["fin_count"] = 0
        df_mapped["rst_count"] = 0
        df_mapped["burst_count"] = 0
        
        # Binary label: 0=normal, 1=attack
        df_mapped["Label"] = (df_mapped["Label"] != 0).astype(int)
        
        print(f"[Dataset] UNSW-NB15: {len(df_mapped)} rows, {df_mapped['Label'].sum()} attacks")
        return df_mapped

    def process_ctu13(self) -> pd.DataFrame:
        """Process CTU-13 botnet dataset (parquet files)."""
        print("[Dataset] Processing CTU-13...")
        
        if not self.ctu_path.exists():
            print(f"[Dataset] CTU-13 path not found")
            return pd.DataFrame()
        
        parquet_files = list(self.ctu_path.glob("*.parquet"))
        if not parquet_files:
            print(f"[Dataset] No CTU-13 parquet files found")
            return pd.DataFrame()
        
        dfs = []
        for pf in parquet_files[:3]:  # Limit to first 3 scenarios for speed
            try:
                df = pd.read_parquet(pf)
                dfs.append(df)
            except Exception as e:
                print(f"[Dataset] Failed to read {pf.name}: {e}")
        
        if not dfs:
            return pd.DataFrame()
        
        df = pd.concat(dfs, ignore_index=True)
        
        # CTU-13 binetflow columns mapping
        feature_map = {
            "Dur": "duration",
            "TotPkts": "total_packets",
            "TotBytes": "total_bytes",
            "SrcBytes": "fwd_bytes",
            "Label": "Label",
        }
        
        df_mapped = pd.DataFrame()
        for ctu_col, our_col in feature_map.items():
            if ctu_col in df.columns:
                df_mapped[our_col] = df[ctu_col]
        
        # Derive features
        df_mapped["mean_pkt_size"] = df_mapped["total_bytes"] / df_mapped["total_packets"].replace(0, 1)
        df_mapped["std_pkt_size"] = 0
        df_mapped["packets_per_sec"] = df_mapped["total_packets"] / df_mapped["duration"].replace(0, 1)
        df_mapped["bytes_per_sec"] = df_mapped["total_bytes"] / df_mapped["duration"].replace(0, 1)
        df_mapped["mean_iat"] = df_mapped["duration"] / df_mapped["total_packets"].replace(0, 1)
        df_mapped["std_iat"] = 0
        df_mapped["fwd_packets"] = df_mapped["total_packets"] * 0.5
        df_mapped["bwd_packets"] = df_mapped["total_packets"] * 0.5
        df_mapped["fwd_bwd_ratio"] = 1.0
        df_mapped["syn_count"] = 0
        df_mapped["ack_count"] = 0
        df_mapped["fin_count"] = 0
        df_mapped["rst_count"] = 0
        df_mapped["retransmit_count"] = 0
        df_mapped["avg_window_size"] = 0
        df_mapped["burst_count"] = 0
        
        # Binary label: background=0, botnet=1
        if "Label" in df_mapped.columns:
            df_mapped["Label"] = df_mapped["Label"].str.contains("Botnet|botnet", na=False).astype(int)
        else:
            df_mapped["Label"] = 0
        
        print(f"[Dataset] CTU-13: {len(df_mapped)} rows, {df_mapped['Label'].sum()} attacks")
        return df_mapped

    def process_cicids2018(self) -> pd.DataFrame:
        """Process CICIDS2018 dataset."""
        print("[Dataset] Processing CICIDS2018...")
        
        if not self.cic2018_path.exists():
            print(f"[Dataset] CICIDS2018 path not found")
            return pd.DataFrame()
        
        csv_files = list(self.cic2018_path.glob("*.csv"))
        if not csv_files:
            print(f"[Dataset] No CICIDS2018 CSV files found")
            return pd.DataFrame()
        
        # Process first 2 files for speed (can be adjusted)
        dfs = []
        for cf in csv_files[:2]:
            try:
                df = pd.read_csv(cf, low_memory=False)
                dfs.append(df)
                print(f"[Dataset] Loaded {cf.name}: {len(df)} rows")
            except Exception as e:
                print(f"[Dataset] Failed to read {cf.name}: {e}")
        
        if not dfs:
            return pd.DataFrame()
        
        df = pd.concat(dfs, ignore_index=True)
        
        # CICIDS2018 column mapping (similar to CIC-IDS2017)
        feature_map = {
            "Flow Duration": "duration",
            "Total Fwd Packets": "fwd_packets",
            "Total Backward Packets": "bwd_packets",
            "Fwd Packet Length Mean": "mean_pkt_size",
            "Fwd Packet Length Std": "std_pkt_size",
            "Flow Bytes/s": "bytes_per_sec",
            "Flow Packets/s": "packets_per_sec",
            "Flow IAT Mean": "mean_iat",
            "Flow IAT Std": "std_iat",
            "FIN Flag Count": "fin_count",
            "SYN Flag Count": "syn_count",
            "RST Flag Count": "rst_count",
            "ACK Flag Count": "ack_count",
            "Init_Win_bytes_forward": "avg_window_size",
            "Label": "Label",
        }
        
        df_mapped = pd.DataFrame()
        for cic_col, our_col in feature_map.items():
            if cic_col in df.columns:
                df_mapped[our_col] = df[cic_col]
        
        # Derive features
        df_mapped["total_packets"] = df_mapped.get("fwd_packets", 0) + df_mapped.get("bwd_packets", 0)
        df_mapped["total_bytes"] = df_mapped.get("total_packets", 0) * df_mapped.get("mean_pkt_size", 0)
        df_mapped["fwd_bwd_ratio"] = df_mapped["fwd_packets"] / df_mapped["bwd_packets"].replace(0, 1)
        df_mapped["retransmit_count"] = 0
        df_mapped["burst_count"] = 0
        
        # Binary label
        if "Label" in df_mapped.columns:
            df_mapped["Label"] = (df_mapped["Label"].str.strip() != "Benign").astype(int)
        else:
            df_mapped["Label"] = 0
        
        print(f"[Dataset] CICIDS2018: {len(df_mapped)} rows, {df_mapped['Label'].sum()} attacks")
        return df_mapped

    def merge_datasets(self) -> Tuple[pd.DataFrame, Dict]:
        """Merge all datasets into unified format."""
        print("[Dataset] Merging all datasets...")
        
        unsw = self.process_unsw_nb15()
        ctu = self.process_ctu13()
        cic2018 = self.process_cicids2018()
        
        # Add dataset source column
        if not unsw.empty:
            unsw["dataset_source"] = "UNSW-NB15"
        if not ctu.empty:
            ctu["dataset_source"] = "CTU-13"
        if not cic2018.empty:
            cic2018["dataset_source"] = "CICIDS2018"
        
        # Combine
        dfs = [df for df in [unsw, ctu, cic2018] if not df.empty]
        if not dfs:
            print("[Dataset] No datasets loaded")
            return pd.DataFrame(), {}
        
        merged = pd.concat(dfs, ignore_index=True)
        
        # Fill NaN with 0
        merged = merged.fillna(0)
        
        # Replace inf with large number
        merged = merged.replace([np.inf, -np.inf], 0)
        
        stats = {
            "total_rows": len(merged),
            "total_attacks": int(merged["Label"].sum()),
            "total_benign": int((merged["Label"] == 0).sum()),
            "unsw_rows": len(unsw) if not unsw.empty else 0,
            "ctu_rows": len(ctu) if not ctu.empty else 0,
            "cic2018_rows": len(cic2018) if not cic2018.empty else 0,
        }
        
        print(f"[Dataset] Merged: {stats['total_rows']} rows, {stats['total_attacks']} attacks")
        return merged, stats
