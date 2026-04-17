# TCP Covert Channel Detector

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](backend/requirements.txt)
[![React 18](https://img.shields.io/badge/React-18-61dafb.svg)](frontend/package.json)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](docker-compose.yml)
[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)

Real-time covert channel & data exfiltration detection using **only TCP/IP metadata** — no payload inspection. Privacy-preserving by design.

---

## Pipeline

```mermaid
flowchart LR
    A[PCAP / Live Capture] --> B[Capture Layer]
    B -->|L3+L4 only| C[Flow Builder]
    C --> D[Feature Extractor<br/>25+ features]
    D --> E1[Rule Scorer<br/>6 rules · 0–100 pts]
    D --> E2[Random Forest<br/>+ SMOTE]
    E1 --> F[SQLite]
    E2 --> F
    F --> G[FastAPI<br/>REST + WebSocket]
    G --> H[React Dashboard]
```

## Detection Logic

```mermaid
flowchart TD
    S[Score = 0] --> R1{std_iat < 0.01<br/>pkts > 10?}
    R1 -->|+30| R2{duration > 60s<br/>pps < 0.5?}
    R1 -->|no| R2
    R2 -->|+25| R3{mean_pkt < 100<br/>pkts > 10?}
    R2 -->|no| R3
    R3 -->|+20| R4{fwd_bwd > 5?}
    R3 -->|no| R4
    R4 -->|+25| R5{bursts > 80%<br/>of pkts?}
    R4 -->|no| R5
    R5 -->|+15| R6{retrans > 10%<br/>of pkts?}
    R5 -->|no| R6
    R6 -->|+10| D{score ≥ 50?}
    R6 -->|no| D
    D -->|yes| ALERT[🚨 Alert]
    D -->|no| OK[✅ Benign]
```

## OSI Layer Coverage

```mermaid
graph TB
    subgraph Inspected
        L3[L3 Network<br/>src_ip · dst_ip · pkt_size · protocol]
        L4[L4 Transport<br/>SYN/ACK/FIN/RST · window · retransmits · ports]
        DER[Derived<br/>IAT · duration · bursts · fwd/bwd ratio]
    end
    subgraph Not Inspected
        L7[L7 Application<br/>payload — never read]
    end
    L3 --> DET[Detector]
    L4 --> DET
    DER --> DET
    L7 -.->|skipped| DET
    style L7 fill:#f5f5f5,stroke:#999,color:#666
    style DER fill:#e3f2fd,stroke:#2196f3
    style L4 fill:#e3f2fd,stroke:#2196f3
    style L3 fill:#e3f2fd,stroke:#2196f3
```

| Layer | What It Catches |
|-------|----------------|
| **L3 — Network** | Who's talking, data volume |
| **L4 — Transport** | Handshake anomalies, flow control abuse |
| **Derived** | Timing patterns, periodicity, asymmetry |
| **L7 — Application** | *Not inspected* |

## Architecture

```mermaid
graph TB
    subgraph Backend [Backend — FastAPI]
        CAP[Capture<br/>scapy] --> FB[FlowBuilder<br/>5-tuple grouping]
        FB --> FE[FeatureExtractor<br/>30+ fields]
        FE --> SC[Scorer<br/>6 rules]
        FE --> ML[FlowDetector<br/>RF + IsolationForest]
        SC --> DB[(SQLite)]
        ML --> DB
        DB --> API[REST + WS API]
    end
    subgraph Frontend [Frontend — React + Chart.js]
        DASH[Dashboard]
        DASH -->|axios| API
        API -->|WebSocket| DASH
    end
```

## Dataset & Training

```mermaid
flowchart LR
    RAW[data/raw/<br/>CIC-IDS2017] -->|scripts/| CLEAN[data/processed/<br/>cleaned CSV]
    CLEAN -->|scripts/| SPLIT[train.csv · test.csv]
    SPLIT --> TRAIN[Undersample 1:10<br/>→ SMOTE 1:1<br/>→ RandomForest]
```

- **Source**: CIC-IDS2017 Infiltration subset (Canadian Institute for Cybersecurity)
- **Imbalance**: 252,754 BENIGN / 36 Infiltration — handled via undersample → SMOTE pipeline
- **Model**: RandomForest (100 estimators, `class_weight="balanced"`)

## Performance

| Metric | Value |
|--------|-------|
| Recall | 85.7% |
| ROC-AUC | 89.5% |
| Accuracy | 98.1% |
| Attack detection (5-fold CV) | 77.8% (28/36 attacks) |

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/flows` | List captured flows |
| `GET` | `/alerts` | Flows with score ≥ threshold |
| `GET` | `/stats` | Aggregate stats + top suspicious IPs |
| `GET` | `/metrics` | Model evaluation metrics |
| `GET` | `/features/importance` | Top features with OSI tags |
| `GET` | `/layers/stats` | Alert counts by OSI layer |
| `GET` | `/report` | Full evaluation report |
| `GET` | `/export/alerts` | Download alerts CSV |
| `POST` | `/capture/start` | Start live capture |
| `POST` | `/capture/stop` | Stop live capture |
| `POST` | `/upload/pcap` | Upload & process PCAP |
| `WS` | `/ws/flows` | Real-time flow stream |

## Quick Start

```bash
# Docker (recommended)
docker compose up --build

# Manual
python scripts/prepare_dataset.py    # clean CIC-IDS2017 → data/processed/
python scripts/split_dataset.py      # 80/20 stratified split
cd backend && pip install -r requirements.txt && uvicorn main:app --port 8000
cd frontend && npm install && npm run dev
```

Open **http://localhost:5173** → upload a PCAP or start live capture.

## Covert Channel Types Detected

| Type | Mechanism | Detection Signal |
|------|-----------|-----------------|
| **Timing** | Data encoded in inter-packet delays | Low `std_iat` |
| **Storage** | Data encoded in TCP header fields | Abnormal flag counts, window sizes |
| **Exfiltration** | Asymmetric data flow out | High `fwd_bwd_ratio` |

## Project Structure

```
├── backend/                 FastAPI + ML pipeline
│   ├── main.py              FastAPI app + WebSocket
│   ├── capture.py           Scapy packet capture
│   ├── flow_builder.py      5-tuple flow grouping
│   ├── feature_extractor.py 30+ statistical features (OSI-tagged)
│   ├── scorer.py            6 rule-based detection rules
│   ├── ml_model.py          RandomForest + IsolationForest
│   ├── evaluator.py         Metrics, cross-validation, reports
│   ├── database.py          Async SQLite layer
│   ├── requirements.txt
│   └── tests/               Unit tests
├── frontend/                React + Chart.js dashboard
│   └── src/components/      UI components
├── data/
│   ├── raw/                 CIC-IDS2017 source CSV (tracked)
│   └── processed/           Cleaned + split CSVs (gitignored)
├── scripts/                 Data preparation scripts
│   ├── prepare_dataset.py
│   └── split_dataset.py
├── docs/                    Evaluation reports
├── .github/workflows/       CI pipeline
├── docker-compose.yml
└── pyproject.toml
```

## Tech Stack

| | |
|---|---|
| **Backend** | Python · FastAPI · Scapy · scikit-learn · imbalanced-learn · SQLite |
| **Frontend** | React · Chart.js · Vite · Axios |
| **Infra** | Docker · docker compose · WebSocket |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, code style, and PR process.

## License

[MIT](LICENSE)
