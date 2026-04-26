"""
New FastAPI endpoints for C++ engine CWND and QoS detection.
Add these to main.py after existing endpoints.
"""

# Add to main.py after existing endpoint definitions:

@app.get("/cpp/status")
async def cpp_engine_status():
    """Check if C++ engine is available."""
    return {
        "available": CPP_ENGINE_AVAILABLE,
        "detectors": {
            "cwnd": CWNDDetectorWrapper is not None,
            "qos": QoSDetectorWrapper is not None
        }
    }


@app.post("/cpp/analyze/cwnd")
async def analyze_cwnd(request: Request):
    """
    Analyze TCP flow for congestion window manipulation using C++ engine.
    
    Body: {
        "packets": [
            {
                "seq_num": int, "ack_num": int, "window_size": int,
                "timestamp": float, "payload_size": int,
                "syn": bool, "ack": bool, "fin": bool, "rst": bool,
                "src_ip": str, "dst_ip": str, "src_port": int, "dst_port": int
            }
        ],
        "sensitivity": float (optional, default 2.5)
    }
    """
    if not CPP_ENGINE_AVAILABLE:
        return {"error": "C++ engine not available", "anomalies": []}
    
    data = await request.json()
    packets = data.get("packets", [])
    sensitivity = data.get("sensitivity", 2.5)
    
    detector = CWNDDetectorWrapper(sensitivity)
    anomalies = detector.analyze_packets(packets)
    
    return {
        "engine": "cpp",
        "detector": "cwnd",
        "packets_analyzed": len(packets),
        "anomalies_found": len(anomalies),
        "anomalies": anomalies
    }


@app.post("/cpp/analyze/qos")
async def analyze_qos(request: Request):
    """
    Analyze IP flow for QoS/DSCP manipulation using C++ engine.
    
    Body: {
        "packets": [
            {
                "dscp": int, "ecn": int, "total_length": int,
                "timestamp": float, "src_ip": str, "dst_ip": str, "ip_id": int
            }
        ],
        "threshold": float (optional, default 0.7)
    }
    """
    if not CPP_ENGINE_AVAILABLE:
        return {"error": "C++ engine not available", "anomalies": []}
    
    data = await request.json()
    packets = data.get("packets", [])
    threshold = data.get("threshold", 0.7)
    
    detector = QoSDetectorWrapper(threshold)
    anomalies = detector.analyze_packets(packets)
    
    return {
        "engine": "cpp",
        "detector": "qos",
        "packets_analyzed": len(packets),
        "anomalies_found": len(anomalies),
        "anomalies": anomalies
    }
