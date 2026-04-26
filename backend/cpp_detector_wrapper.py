"""
Python wrapper for C++ covert channel detection engine.
Provides high-level interface for CWND and QoS detection.
"""
import sys
from pathlib import Path

try:
    import covert_engine
    CPP_ENGINE_AVAILABLE = True
except ImportError:
    CPP_ENGINE_AVAILABLE = False
    print("Warning: C++ engine not available. Build with: cd cpp_engine && build.bat")


class CWNDDetectorWrapper:
    """Wrapper for C++ CWND detector with Python-friendly interface."""
    
    def __init__(self, sensitivity=2.5):
        if not CPP_ENGINE_AVAILABLE:
            raise RuntimeError("C++ engine not available")
        self.detector = covert_engine.CWNDDetector(sensitivity)
    
    def analyze_packets(self, packets_data):
        """
        Analyze TCP packets for congestion window manipulation.
        
        Args:
            packets_data: List of dicts with keys: seq_num, ack_num, window_size,
                         timestamp, payload_size, syn, ack, fin, rst, src_ip, dst_ip,
                         src_port, dst_port
        
        Returns:
            List of anomaly dicts with keys: timestamp, expected_cwnd, observed_cwnd,
            deviation_score, anomaly_type, flow_id
        """
        tcp_packets = []
        for pkt in packets_data:
            tcp_pkt = covert_engine.TCPPacket()
            tcp_pkt.seq_num = pkt.get('seq_num', 0)
            tcp_pkt.ack_num = pkt.get('ack_num', 0)
            tcp_pkt.window_size = pkt.get('window_size', 0)
            tcp_pkt.timestamp = pkt.get('timestamp', 0.0)
            tcp_pkt.payload_size = pkt.get('payload_size', 0)
            tcp_pkt.syn = pkt.get('syn', False)
            tcp_pkt.ack = pkt.get('ack', False)
            tcp_pkt.fin = pkt.get('fin', False)
            tcp_pkt.rst = pkt.get('rst', False)
            tcp_pkt.src_ip = pkt.get('src_ip', '')
            tcp_pkt.dst_ip = pkt.get('dst_ip', '')
            tcp_pkt.src_port = pkt.get('src_port', 0)
            tcp_pkt.dst_port = pkt.get('dst_port', 0)
            tcp_packets.append(tcp_pkt)
        
        anomalies = self.detector.analyze_flow(tcp_packets)
        
        return [
            {
                'timestamp': a.timestamp,
                'expected_cwnd': a.expected_cwnd,
                'observed_cwnd': a.observed_cwnd,
                'deviation_score': a.deviation_score,
                'anomaly_type': a.anomaly_type,
                'flow_id': a.flow_id
            }
            for a in anomalies
        ]


class QoSDetectorWrapper:
    """Wrapper for C++ QoS detector with Python-friendly interface."""
    
    def __init__(self, threshold=0.7):
        if not CPP_ENGINE_AVAILABLE:
            raise RuntimeError("C++ engine not available")
        self.detector = covert_engine.QoSDetector(threshold)
    
    def analyze_packets(self, packets_data):
        """
        Analyze IP packets for QoS/DSCP manipulation.
        
        Args:
            packets_data: List of dicts with keys: dscp, ecn, total_length,
                         timestamp, src_ip, dst_ip, ip_id
        
        Returns:
            List of anomaly dicts with keys: timestamp, dscp_value, frequency,
            expected_frequency, anomaly_type, score, flow_id
        """
        ip_packets = []
        for pkt in packets_data:
            ip_pkt = covert_engine.IPPacket()
            ip_pkt.dscp = pkt.get('dscp', 0)
            ip_pkt.ecn = pkt.get('ecn', 0)
            ip_pkt.total_length = pkt.get('total_length', 0)
            ip_pkt.timestamp = pkt.get('timestamp', 0.0)
            ip_pkt.src_ip = pkt.get('src_ip', '')
            ip_pkt.dst_ip = pkt.get('dst_ip', '')
            ip_pkt.ip_id = pkt.get('ip_id', 0)
            ip_packets.append(ip_pkt)
        
        anomalies = self.detector.analyze_dscp_patterns(ip_packets)
        
        return [
            {
                'timestamp': a.timestamp,
                'dscp_value': a.dscp_value,
                'frequency': a.frequency,
                'expected_frequency': a.expected_frequency,
                'anomaly_type': a.anomaly_type,
                'score': a.score,
                'flow_id': a.flow_id
            }
            for a in anomalies
        ]
