# Contributing to TCP Covert Channel Detector

## Development Setup

```bash
# Clone and prepare dataset
git clone <repo-url>
cd tcp-covert-channel-detector
python scripts/prepare_dataset.py    # clean CIC-IDS2017
python scripts/split_dataset.py      # 80/20 train/test split

# Backend
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

## Project Structure

```
backend/          FastAPI + ML pipeline
  capture.py      Scapy packet capture
  flow_builder.py 5-tuple flow grouping
  feature_extractor.py  30+ statistical features
  scorer.py       Rule-based detection (6 rules)
  ml_model.py     RandomForest + IsolationForest
  evaluator.py    Metrics + cross-validation
  database.py     SQLite async layer
  main.py         FastAPI endpoints + WebSocket

frontend/         React + Chart.js dashboard
  src/components/ UI components
  src/App.jsx     Main application

scripts/           Data preparation scripts
data/
  raw/             CIC-IDS2017 source CSV (tracked)
  processed/       Generated train/test splits (gitignored)
docs/             Evaluation reports
```

## Code Style

- **Python**: Follow PEP 8, use type hints where helpful
- **JavaScript**: ES6+, functional components with hooks
- **Commits**: Conventional commits (`feat:`, `fix:`, `docs:`, `refactor:`)

## Adding Detection Rules

Edit `backend/scorer.py`:

```python
# Add new rule
if <condition>:
    points += <weight>
    reasons.append("<Layer>: <description>")
```

Update `backend/evaluator.py` SCORING_RULES constant for documentation.

## Testing

```bash
# Backend
cd backend
python -m pytest  # if tests exist

# Frontend
cd frontend
npm run build  # verify build succeeds
```

## Pull Request Process

1. Fork the repo
2. Create feature branch (`git checkout -b feat/new-detection-rule`)
3. Commit changes (`git commit -m 'feat: add TCP window manipulation detection'`)
4. Push to branch (`git push origin feat/new-detection-rule`)
5. Open PR with description of changes

## Dataset Notes

- CIC-IDS2017 Infiltration CSV (79MB) is included in `data/raw/`
- Run `python scripts/prepare_dataset.py` then `python scripts/split_dataset.py`

## License

MIT - see LICENSE file
