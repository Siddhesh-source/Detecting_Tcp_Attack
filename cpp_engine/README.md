# C++ Covert Channel Detection Engine

High-performance C++ implementation for detecting Computer Networks covert channels.

## Features

### 1. TCP Congestion Window (CWND) Manipulation Detection
Detects covert channels that exploit TCP congestion control algorithms:
- **Artificial Inflation**: Sustained CWND growth without expected sawtooth pattern
- **Sawtooth Encoding**: Data encoded in periodic CWND oscillations
- **Window Oscillation**: Abnormal variance in congestion window behavior

**Algorithms Modeled**:
- TCP Reno (AIMD - Additive Increase Multiplicative Decrease)
- TCP CUBIC (cubic growth function)

### 2. QoS/DSCP Field Manipulation Detection
Detects covert channels using Quality of Service fields:
- **DSCP Hopping**: Rapid transitions between DiffServ Code Points
- **Priority Encoding**: Data encoded in priority class selection
- **ECN Abuse**: Explicit Congestion Notification field manipulation

## Build Instructions

### Prerequisites
- CMake 3.15+
- C++17 compiler (MSVC 2022, GCC 9+, or Clang 10+)
- Python 3.10+
- pybind11

### Windows Build
```bash
cd cpp_engine
build.bat
```

### Manual Build
```bash
cd cpp_engine
python -m pip install pybind11
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
copy Release\covert_engine*.pyd ..\backend\
```

## Usage

### Python API
```python
from cpp_detector_wrapper import CWNDDetectorWrapper, QoSDetectorWrapper

# CWND Detection
cwnd_detector = CWNDDetectorWrapper(sensitivity=2.5)
tcp_packets = [
    {
        'seq_num': 1000, 'ack_num': 2000, 'window_size': 65535,
        'timestamp': 1234567890.0, 'payload_size': 1460,
        'syn': False, 'ack': True, 'fin': False, 'rst': False,
        'src_ip': '192.168.1.10', 'dst_ip': '10.0.0.1',
        'src_port': 50000, 'dst_port': 443
    }
]
anomalies = cwnd_detector.analyze_packets(tcp_packets)

# QoS Detection
qos_detector = QoSDetectorWrapper(threshold=0.7)
ip_packets = [
    {
        'dscp': 46, 'ecn': 0, 'total_length': 1500,
        'timestamp': 1234567890.0,
        'src_ip': '192.168.1.10', 'dst_ip': '10.0.0.1',
        'ip_id': 12345
    }
]
anomalies = qos_detector.analyze_packets(ip_packets)
```

### REST API
```bash
# Check engine status
curl http://localhost:8000/cpp/status

# Analyze CWND
curl -X POST http://localhost:8000/cpp/analyze/cwnd \
  -H "Content-Type: application/json" \
  -d '{"packets": [...], "sensitivity": 2.5}'

# Analyze QoS
curl -X POST http://localhost:8000/cpp/analyze/qos \
  -H "Content-Type: application/json" \
  -d '{"packets": [...], "threshold": 0.7}'
```

## Performance

- **Throughput**: 10-100x faster than Python implementation
- **Memory**: Zero-copy packet processing
- **Latency**: Sub-millisecond detection for typical flows

## Patent Claims

### Novel Contributions
1. **Real-time CWND anomaly detection** using statistical deviation from RFC-compliant congestion control algorithms
2. **Multi-algorithm CWND modeling** (Reno + CUBIC) for baseline comparison
3. **QoS field entropy analysis** for detecting covert signaling patterns
4. **Combined temporal and statistical analysis** for high-accuracy detection

### Key Differentiators
- Privacy-preserving (no payload inspection)
- Works on encrypted traffic
- Low false positive rate through multi-pattern correlation
- Explainable detection (specific anomaly types identified)
