# Available Datasets

## Location
All datasets are stored in `D:\CN\` root directory in separate archive folders.

## 1. UNSW-NB15 (archive/)
**Source**: University of New South Wales  
**Files**: 8 files (586 MB total)
- `UNSW-NB15_1.csv` through `UNSW-NB15_4.csv` - Raw captures
- `UNSW_NB15_training-set.csv` (15.4 MB)
- `UNSW_NB15_testing-set.csv` (32.3 MB)
- `NUSW-NB15_features.csv` - Feature descriptions
- `UNSW-NB15_LIST_EVENTS.csv` - Event catalog

**Attack Types**: 9 categories including Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms

## 2. CTU-13 (archive (1)/)
**Source**: Czech Technical University  
**Files**: 13 botnet scenarios (120 MB total, parquet format)
- Neris botnet (3 captures)
- Rbot botnet (4 captures)
- Virut botnet (2 captures)
- Menti, Sogou, Murlo, NsisAy (1 each)

**Format**: `.binetflow.parquet` - bidirectional NetFlow data  
**Date Range**: August 2011

## 3. CICIDS2018 (archive (2)/)
**Source**: Canadian Institute for Cybersecurity  
**Files**: 10 daily captures (6.4 GB total)
- February 14-23, 2018
- February 28, 2018
- March 1-2, 2018

**Attack Types**: Brute Force, Heartbleed, Botnet, DoS, DDoS, Web attacks, Infiltration

## Integration Status
- **Currently Used**: CIC-IDS2017 (Infiltration subset) in `data/processed/`
- **Available for Integration**: All three datasets above
- **Next Steps**: Merge datasets for multi-source training pipeline

## Recommended Usage
1. **UNSW-NB15**: Broader attack coverage, modern network patterns
2. **CTU-13**: Botnet-specific detection, C&C channel patterns
3. **CICIDS2018**: Recent attack vectors, DDoS variants

## Feature Mapping Required
Each dataset has different column schemas - preprocessing scripts needed to map to our 17 FEATURE_COLS in `ml_model.py`.
