"""
FastAPI backend for tcp-covert-channel-detector.

STARTUP SEQUENCE (in order):
  1. init_db()
  2. detector.fit_supervised("data/train.csv")
  3. metrics = evaluate_model(detector, "data/test.csv")
  4. Store metrics in app.state.metrics
  5. Log accuracy and F1 to console

ENDPOINTS:
  GET  /flows              - all flows (limit param)
  GET  /alerts             - flows where suspicion_score >= threshold (default 50)
  GET  /stats              - aggregate stats + top 5 suspicious IPs
  GET  /metrics            - model evaluation (accuracy, precision, recall, F1, cm)
  GET  /features/importance - top features with OSI layer tags
  GET  /layers/stats       - alert counts grouped by OSI layer
  POST /capture/start      - body: {"interface": "eth0"}
  POST /capture/stop
  POST /upload/pcap         - file upload
  GET  /export/alerts      - CSV download

WEBSOCKET:
  ws://localhost:8000/ws/flows  - broadcast each new flow as JSON
"""

import asyncio
import io
import os
import time
from contextlib import asynccontextmanager
from typing import Optional

from advanced_detection import AdvancedCovertChannelDetector
from alerting import AlertManager
from behavioral_baseline import BehavioralBaseline
from capture import capture_live, read_pcap
from config import SMTP_CONFIG
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
from explainability import ExplainabilityEngine
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
from feature_extractor import extract_features
from flow_builder import FlowBuilder
from forensics import ForensicCollector
from ml_model import FlowDetector
from network_topology import NetworkTopology
from protocol_scorer import score_dns_flow, score_icmp_flow, score_udp_flow
from scorer import compute_suspicion
from threat_intel import ThreatIntelligence

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
_background_tasks: set[asyncio.Task] = set()

# New modules
alert_manager = AlertManager(SMTP_CONFIG)
behavioral_baseline = BehavioralBaseline()
advanced_detector = AdvancedCovertChannelDetector()
network_topology = NetworkTopology()
forensic_collector = ForensicCollector()
threat_intel = ThreatIntelligence()
explainability_engine: Optional[ExplainabilityEngine] = None


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
    
    # Initialize new modules
    global explainability_engine
    explainability_engine = ExplainabilityEngine(detector)
    alert_manager.start()
    
    # Populate network topology from existing flows
    flows = await get_all_flows(1000)
    for flow in flows:
        network_topology.add_flow(flow)
        behavioral_baseline.update_profile(flow)
    
    print(f"[Startup] 7/7  New modules initialized (SHAP, Alerts, Baseline, Topology)")
    print(f"[Startup] Topology: {len(network_topology.graph.nodes)} nodes, {len(network_topology.graph.edges)} edges")
    print("[Startup] Backend ready")

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

        # Add to forensic ring buffer
        forensic_collector.add_packet(pkt)

        flow_builder.add_packet(pkt)
        completed = flow_builder.get_completed_flows(timeout=30)

        for flow in completed:
            # Extract features
            features = extract_features(flow)

            # Protocol-specific scoring
            protocol = features.get("protocol", "TCP")
            if protocol == "UDP":
                proto_score, proto_reasons = score_udp_flow(features)
            elif protocol == "ICMP":
                proto_score, proto_reasons = score_icmp_flow(features)
            elif protocol == "DNS":
                proto_score, proto_reasons = score_dns_flow(features)
            else:
                proto_score, proto_reasons = 0.0, []

            # TCP scoring
            tcp_score, tcp_reasons = compute_suspicion(features)
            
            # Advanced covert channel detection
            advanced_results = advanced_detector.analyze_flow(flow.packets)
            
            # Combine scores
            score = max(tcp_score, proto_score, advanced_results["total_score"])
            reasons = tcp_reasons + proto_reasons + advanced_results["detected_techniques"]

            # ML prediction
            is_anomaly = score >= 50
            predicted_label = "ATTACK" if is_anomaly else "BENIGN"
            true_label = "UNKNOWN"

            flow_dict = {
                **features,
                "suspicion_score": score,
                "alert_reasons": "; ".join(reasons),
                "is_anomaly": int(is_anomaly),
                "predicted_label": predicted_label,
                "true_label": true_label,
                "created_at": time.time(),
            }

            # Behavioral baseline check
            behavioral_baseline.update_profile(flow_dict)
            anomaly_result = behavioral_baseline.detect_anomaly(flow_dict)
            if anomaly_result["is_anomaly"]:
                flow_dict["suspicion_score"] = min(flow_dict["suspicion_score"] + anomaly_result["anomaly_score"], 100)
                flow_dict["alert_reasons"] += f"; {anomaly_result['reason']}"

            # Threat intelligence enrichment
            threat_enrichment = threat_intel.enrich_flow(flow_dict)
            flow_dict.update(threat_enrichment)

            # Network topology
            network_topology.add_flow(flow_dict)

            # Insert into database
            await insert_flow(flow_dict)

            # Send alert if needed
            if alert_manager.should_alert(flow_dict):
                await alert_manager.send_alert(flow_dict)

            # Capture evidence for high-severity alerts
            if flow_dict["suspicion_score"] >= 70:
                context_packets = forensic_collector.get_context_packets(flow_dict)
                forensic_collector.capture_flow_evidence(flow_dict, context_packets)

            # Broadcast to WebSocket
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
    Start live capture on specified interface.
    Body: {"interface": "eth0"} or {"interface": "\\Device\\NPF_{GUID}"} on Windows
    """
    global capture_task, stop_event

    try:
        body = await request.json()
        interface = body.get("interface", "")
        
        if not interface:
            return {"status": "error", "message": "Interface name required"}
        
        print(f"[API] Capture start requested for interface: {interface}")
        
        if capture_task and not capture_task.done():
            print(f"[API] Capture already running")
            return {"status": "already_running", "interface": interface}

        stop_event.clear()
        
        # Start capture task
        capture_task = asyncio.create_task(capture_live(interface, packet_queue, stop_event))
        print(f"[API] Capture task created")
        
        # Start processing loop
        task = asyncio.create_task(_process_packets())
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)
        print(f"[API] Processing task created")
        
        return {"status": "started", "interface": interface, "message": "Capture started successfully"}
    
    except Exception as e:
        print(f"[API] Capture start error: {e}")
        return {"status": "error", "message": str(e)}


# ----- Capture stop ----------------------------------------------------
@app.post("/capture/stop")
async def stop_capture():
    """Stop live capture."""
    global stop_event, capture_task
    
    print(f"[API] Capture stop requested")
    stop_event.set()
    
    if capture_task:
        try:
            await asyncio.wait_for(capture_task, timeout=5.0)
            print(f"[API] Capture task stopped cleanly")
        except asyncio.TimeoutError:
            print(f"[API] Capture task timeout, cancelling")
            capture_task.cancel()
    
    return {"status": "stopped"}


# ----- Get available network interfaces --------------------------------
@app.get("/capture/interfaces")
async def list_interfaces():
    """List available network interfaces for capture."""
    try:
        from scapy.all import get_if_list, get_if_addr
        interfaces = get_if_list()
        
        # Format interface list with IPs
        interface_list = []
        for iface in interfaces:
            try:
                addr = get_if_addr(iface)
                interface_list.append({
                    "name": iface,
                    "ip": addr if addr != "0.0.0.0" else "No IP"
                })
            except:
                interface_list.append({"name": iface, "ip": "Unknown"})
        
        print(f"[API] Available interfaces: {len(interface_list)}")
        return {"interfaces": interface_list}
    except Exception as e:
        print(f"[API] Error listing interfaces: {e}")
        return {"interfaces": [], "error": str(e)}


# ----- PCAP upload -----------------------------------------------------
@app.post("/upload/pcap")
async def upload_pcap(file: UploadFile = File(...)):
    import tempfile

    tmp = os.path.join(tempfile.gettempdir(), file.filename)
    with open(tmp, "wb") as f:
        f.write(await file.read())

    await read_pcap(tmp, packet_queue)
    task = asyncio.create_task(_process_packets())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
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
        headers={"Content-Disposition": "attachment; filename=alerts.csv"},
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


# ======================================================================
# NEW ENDPOINTS - Enhanced Features
# ======================================================================

# ----- SHAP Explainability ---------------------------------------------
@app.get("/explain/{flow_id:path}")
async def explain_flow(flow_id: str):
    """Get SHAP explanation for a specific flow."""
    if explainability_engine is None:
        return {"error": "Explainability engine not initialized"}
    
    flows = await get_all_flows(1000)
    flow = next((f for f in flows if f.get("flow_id") == flow_id), None)
    if not flow:
        return {"error": "Flow not found"}
    
    try:
        explanation = explainability_engine.explain_prediction(flow)
        return explanation
    except Exception as e:
        return {"error": str(e)}


@app.get("/explain/global")
async def global_feature_importance():
    """Get global feature importance using SHAP."""
    if explainability_engine is None:
        return {"error": "Explainability engine not initialized"}
    
    # Sample recent flows
    flows = await get_all_flows(100)
    if not flows:
        return {"error": "No flows available"}
    
    import numpy as np
    X_sample = np.array([[
        flow.get(col, 0) for col in detector._flow_to_array(flow)[0]
    ] for flow in flows[:50]])
    
    importance = explainability_engine.get_global_feature_importance(X_sample)
    return {"importance": importance}


# ----- Network Topology ------------------------------------------------
@app.get("/topology/graph")
async def topology_graph():
    """Get network graph data for visualization."""
    return network_topology.get_graph_data()


@app.get("/topology/centrality")
async def topology_centrality():
    """Get node centrality metrics."""
    return {"centrality": network_topology.get_centrality_metrics()}


@app.get("/topology/communities")
async def topology_communities():
    """Get detected network communities."""
    return {"communities": network_topology.detect_communities()}


@app.get("/topology/top-talkers")
async def topology_top_talkers(limit: int = Query(default=10, le=50)):
    """Get nodes with highest traffic."""
    return {"top_talkers": network_topology.get_top_talkers(limit)}


# ----- Behavioral Baseline ---------------------------------------------
@app.get("/baseline/stats")
async def baseline_stats():
    """Get behavioral baseline statistics."""
    return behavioral_baseline.get_profile_stats()


@app.get("/baseline/profile/{ip}")
async def baseline_profile(ip: str):
    """Get traffic profile for specific IP."""
    if ip in behavioral_baseline.profiles:
        profile = behavioral_baseline.profiles[ip]
        return {
            "ip": profile.ip,
            "flow_count": profile.flow_count,
            "total_bytes": profile.total_bytes,
            "avg_duration": profile.avg_duration,
            "protocols": profile.protocols,
            "top_ports": sorted(profile.ports.items(), key=lambda x: x[1], reverse=True)[:10]
        }
    return {"error": "Profile not found"}


@app.get("/baseline/circadian/{ip}")
async def baseline_circadian(ip: str):
    """Get hourly activity pattern for IP."""
    pattern = behavioral_baseline.get_circadian_pattern(ip)
    if pattern:
        return {"ip": ip, "hourly_activity": pattern}
    return {"error": "Profile not found"}


# ----- Forensics -------------------------------------------------------
@app.get("/forensics/timeline/{flow_id}")
async def forensics_timeline(flow_id: str):
    """Get forensic timeline for captured flow."""
    timeline = forensic_collector.generate_timeline(flow_id)
    if timeline:
        return timeline
    return {"error": "Timeline not found"}


@app.get("/forensics/evidence")
async def forensics_evidence():
    """List captured evidence files."""
    evidence_files = list(forensic_collector.evidence_dir.glob("*.pcap"))
    return {
        "evidence_files": [
            {
                "filename": f.name,
                "size": f.stat().st_size,
                "created": f.stat().st_ctime
            }
            for f in evidence_files
        ]
    }


@app.post("/forensics/cleanup")
async def forensics_cleanup(max_age_days: int = Query(default=30)):
    """Clean up old evidence files."""
    removed = forensic_collector.cleanup_old_evidence(max_age_days)
    return {"removed": removed}


# ----- Threat Intelligence ---------------------------------------------
@app.get("/threat-intel/lookup/{ip}")
async def threat_intel_lookup(ip: str):
    """Lookup IP reputation."""
    reputation = await threat_intel.lookup_ip(ip)
    return {
        "ip": reputation.ip,
        "is_malicious": reputation.is_malicious,
        "reputation_score": reputation.reputation_score,
        "threat_types": reputation.threat_types,
        "sources": reputation.sources
    }


@app.get("/threat-intel/stats")
async def threat_intel_stats():
    """Get threat intelligence statistics."""
    return threat_intel.get_stats()


# ----- Alert Configuration ---------------------------------------------
@app.get("/alerts/config")
async def get_alert_config():
    """Get current alert configuration."""
    return {
        "smtp_host": alert_manager.config.smtp_host,
        "smtp_port": alert_manager.config.smtp_port,
        "from_email": alert_manager.config.from_email,
        "to_emails": alert_manager.config.to_emails,
        "min_severity": alert_manager.config.min_severity,
        "dedup_window": alert_manager.config.dedup_window,
        "enabled": alert_manager.config.enabled
    }


@app.post("/alerts/config")
async def update_alert_config(request: Request):
    """Update alert configuration."""
    config = await request.json()
    alert_manager.config.enabled = config.get("enabled", alert_manager.config.enabled)
    alert_manager.config.min_severity = config.get("min_severity", alert_manager.config.min_severity)
    alert_manager.config.to_emails = config.get("to_emails", alert_manager.config.to_emails)
    return {"status": "updated"}


@app.post("/alerts/test")
async def test_alert():
    """Send test alert email."""
    test_flow = {
        "flow_id": "test:80->test:443",
        "src_ip": "192.168.1.100",
        "src_port": 80,
        "dst_ip": "10.0.0.1",
        "dst_port": 443,
        "protocol": "TCP",
        "suspicion_score": 75,
        "alert_reasons": "Test alert",
        "duration": 10.5,
        "total_packets": 100,
        "total_bytes": 50000,
        "mean_iat": 0.001,
        "std_iat": 0.0005,
        "created_at": time.time()
    }
    await alert_manager.send_alert(test_flow)
    return {"status": "test_alert_sent"}
