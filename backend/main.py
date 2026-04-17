"""
FastAPI backend for tcp-covert-channel-detector.

STARTUP SEQUENCE (in order):
  1. init_db()
  2. detector.fit_supervised("data/train.csv")
  3. metrics = evaluate_model(detector, "data/test.csv")
  4. Store metrics in app.state.metrics
  5. Log accuracy and F1 to console

ENDPOINTS:
  GET  /flows              – all flows (limit param)
  GET  /alerts             – flows where suspicion_score >= threshold (default 50)
  GET  /stats              – aggregate stats + top 5 suspicious IPs
  GET  /metrics            – model evaluation (accuracy, precision, recall, F1, cm)
  GET  /features/importance – top features with OSI layer tags
  GET  /layers/stats       – alert counts grouped by OSI layer
  POST /capture/start      – body: {"interface": "eth0"}
  POST /capture/stop
  POST /upload/pcap         – file upload
  GET  /export/alerts      – CSV download

WEBSOCKET:
  ws://localhost:8000/ws/flows  – broadcast each new flow as JSON
"""

import asyncio
import io
import os
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import (
    FastAPI,
    File,
    Query,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from capture import capture_live, read_pcap
from database import (
    get_alerts,
    get_alerts_for_export,
    get_all_flows,
    get_layer_stats,
    get_stats,
    init_db,
    insert_flow,
)
from evaluator import (
    evaluate_model,
    generate_evaluation_report,
    get_feature_importance,
    save_evaluation_report,
)
from feature_extractor import extract_features
from flow_builder import FlowBuilder
from ml_model import FlowDetector
from scorer import compute_suspicion

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BACKEND_DIR)
TRAIN_CSV = os.path.join(PROJECT_DIR, "data", "processed", "train.csv")
TEST_CSV = os.path.join(PROJECT_DIR, "data", "processed", "test.csv")

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
flow_builder = FlowBuilder()
capture_task: Optional[asyncio.Task] = None
stop_event = asyncio.Event()
packet_queue: asyncio.Queue = asyncio.Queue()
detector = FlowDetector()


# ======================================================================
# STARTUP / SHUTDOWN  (lifespan)
# ======================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup sequence — runs exactly in this order:
      1. init_db()
      2. detector.fit_supervised(train_csv)
      3. metrics = evaluate_model(detector, test_csv)
      4. Store metrics in app.state.metrics
      5. Log accuracy and F1
    """
    global detector

    # 1. Initialise database
    await init_db()
    print("[Startup] 1/5  Database initialised")

    # 2. Train supervised model on labelled CIC-IDS2017 data
    if os.path.exists(TRAIN_CSV):
        detector.fit_supervised(TRAIN_CSV)
        print("[Startup] 2/5  Supervised model trained")
    else:
        # Try loading from disk if no train CSV
        detector = FlowDetector.load()
        print(f"[Startup] 2/5  Model loaded from disk (mode={detector.mode})")

    # 3. Evaluate on test set immediately
    if detector.is_trained and os.path.exists(TEST_CSV):
        metrics = evaluate_model(detector, TEST_CSV)
        print("[Startup] 3/5  Model evaluated on test set")
    else:
        metrics = {"error": "Model not trained or test data missing"}
        print("[Startup] 3/5  Evaluation skipped — model not trained or no test data")

    # 4. Store metrics in app.state
    app.state.metrics = metrics
    print("[Startup] 4/5  Metrics stored in app.state.metrics")

    # 5. Log accuracy and F1, generate evaluation report
    acc = metrics.get("accuracy", "N/A")
    f1 = metrics.get("f1", "N/A")
    print(f"[Startup] 5/5  accuracy={acc}, F1={f1}")

    # Generate and save evaluation report → docs/evaluation_report.md
    report = generate_evaluation_report(detector, metrics)
    report_path = save_evaluation_report(report)
    app.state.eval_report = report
    print(f"[Startup] 6/6  Evaluation report saved to {report_path}")
    print("[Startup] ✅  Backend ready")

    yield


# ======================================================================
# App
# ======================================================================
app = FastAPI(title="TCP Covert Channel Detector", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ======================================================================
# BACKGROUND LOOP — drain packet queue → flows → features → score → DB → WS
# ======================================================================
async def _process_packets():
    """
    Consume packets from the queue, build flows, extract features,
    score, predict, insert into DB, and broadcast via WebSocket.
    """
    while True:
        pkt = await packet_queue.get()
        if pkt is None:  # sentinel
            break

        flow_builder.add_packet(pkt)
        completed = flow_builder.get_completed_flows(timeout=30)

        for flow in completed:
            # Extract features (includes tcp_layer, feature_layer_map)
            features = extract_features(flow)

            # Rule-based scoring (0–100 points)
            score, reasons = compute_suspicion(features)

            # ML prediction
            is_anomaly = score >= 50
            predicted_label = "ATTACK" if is_anomaly else "BENIGN"
            true_label = "UNKNOWN"  # no ground truth for live traffic

            flow_dict = {
                **features,
                "suspicion_score": score,
                "alert_reasons": "; ".join(reasons),
                "is_anomaly": int(is_anomaly),
                "predicted_label": predicted_label,
                "true_label": true_label,
                "created_at": time.time(),
            }

            # Insert into database
            await insert_flow(flow_dict)

            # Broadcast to WebSocket subscribers
            # Include ALL fields — alert_reasons and tcp_layer
            await _broadcast(flow_dict)


# ======================================================================
# WEBSOCKET — ws://localhost:8000/ws/flows
# ======================================================================
_ws_clients: list[WebSocket] = []


async def _broadcast(flow_dict: dict):
    """Push each new flow as JSON to all connected WS clients."""
    dead = []
    for ws in _ws_clients:
        try:
            await ws.send_json(flow_dict)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.remove(ws)


@app.websocket("/ws/flows")
async def ws_flows(ws: WebSocket):
    """
    WebSocket endpoint that broadcasts each new flow as JSON
    immediately after processing.  All fields are included.
    """
    await ws.accept()
    _ws_clients.append(ws)
    try:
        while True:
            await ws.receive_text()  # keep connection alive
    except WebSocketDisconnect:
        _ws_clients.remove(ws)


# ======================================================================
# REST ENDPOINTS
# ======================================================================

# ----- Flows -----------------------------------------------------------
@app.get("/flows")
async def list_flows(limit: int = Query(default=100, le=1000)):
    rows = await get_all_flows(limit)
    return {"flows": rows}


# ----- Alerts ----------------------------------------------------------
@app.get("/alerts")
async def list_alerts(threshold: float = Query(default=50, ge=0, le=100)):
    rows = await get_alerts(threshold)
    return {"alerts": rows}


# ----- Stats -----------------------------------------------------------
@app.get("/stats")
async def stats():
    s = await get_stats()
    return s


# ----- Model metrics ---------------------------------------------------
@app.get("/metrics")
async def metrics(request: Request):
    """Returns app.state.metrics dict (accuracy, precision, recall, F1, cm)."""
    return request.app.state.metrics


# ----- Feature importance ----------------------------------------------
@app.get("/features/importance")
async def features_importance():
    """Top features by importance with OSI layer tags."""
    return {"features": get_feature_importance(detector)}


# ----- Layer stats -----------------------------------------------------
@app.get("/layers/stats")
async def layers_stats():
    """
    Count of alerts grouped by tcp_layer field.
    Format: {"Transport": 45, "Derived": 30, "Network": 10}
    """
    stats = await get_layer_stats()
    return stats


# ----- Capture start ---------------------------------------------------
@app.post("/capture/start")
async def start_capture(request: Request):
    """
    Start live TCP capture.
    Body: {"interface": "eth0"}
    """
    global capture_task, stop_event

    body = await request.json()
    interface = body.get("interface", "eth0")

    if capture_task and not capture_task.done():
        return {"status": "already_running"}

    stop_event.clear()
    capture_task = asyncio.create_task(
        capture_live(interface, packet_queue, stop_event)
    )
    # Start the processing loop too
    asyncio.create_task(_process_packets())
    return {"status": "started", "interface": interface}


# ----- Capture stop ----------------------------------------------------
@app.post("/capture/stop")
async def stop_capture():
    global stop_event
    stop_event.set()
    return {"status": "stopped"}


# ----- PCAP upload -----------------------------------------------------
@app.post("/upload/pcap")
async def upload_pcap(file: UploadFile = File(...)):
    import tempfile
    tmp = os.path.join(tempfile.gettempdir(), file.filename)
    with open(tmp, "wb") as f:
        f.write(await file.read())

    await read_pcap(tmp, packet_queue)
    asyncio.create_task(_process_packets())
    return {"status": "pcap_queued", "filename": file.filename}


# ----- Export alerts as CSV --------------------------------------------
@app.get("/export/alerts")
async def export_alerts(threshold: float = Query(default=50, ge=0, le=100)):
    """Download alerts above threshold as a CSV file."""
    csv_data = await get_alerts_for_export(threshold)
    if not csv_data:
        return {"message": "No alerts to export"}

    return StreamingResponse(
        io.StringIO(csv_data),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=alerts.csv"
        },
    )


# ----- Evaluation report -----------------------------------------------
@app.get("/report")
async def evaluation_report(request: Request):
    """Return the evaluation report markdown string."""
    report = getattr(request.app.state, "eval_report", None)
    if report is None:
        return {"error": "Evaluation report not available"}
    return {"report": report}


# ----- Health ----------------------------------------------------------
@app.get("/health")
async def health(request: Request):
    return {
        "status": "ok",
        "model_mode": detector.mode,
        "model_trained": detector.is_trained,
        "metrics_cached": hasattr(request.app.state, "metrics"),
    }
