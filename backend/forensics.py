"""
PCAP evidence collection for forensic analysis.
Captures packet snippets for suspicious flows with ring buffer support.
"""

from __future__ import annotations

import os
import time
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional
from pathlib import Path

try:
    from scapy.all import wrpcap, Ether, IP, TCP, UDP, ICMP
except ImportError:
    wrpcap = Ether = IP = TCP = UDP = ICMP = None


@dataclass
class PacketCapture:
    """Captured packet metadata."""
    flow_id: str
    timestamp: float
    packets: List[dict]
    pcap_path: Optional[str] = None


class ForensicCollector:
    """Collects PCAP evidence for suspicious flows."""

    def __init__(self, evidence_dir: str = "evidence", ring_buffer_size: int = 1000):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(exist_ok=True)
        self.ring_buffer_size = ring_buffer_size
        self.packet_buffer: deque = deque(maxlen=ring_buffer_size)
        self.captured_flows: Dict[str, PacketCapture] = {}

    def add_packet(self, packet_dict: dict):
        """Add packet to ring buffer."""
        self.packet_buffer.append(packet_dict)

    def capture_flow_evidence(self, flow: Dict, packets: List[dict]) -> str:
        """
        Capture PCAP snippet for suspicious flow.
        Returns path to saved PCAP file.
        """
        flow_id = flow.get("flow_id", "unknown")
        timestamp = int(time.time())
        
        # Create filename
        safe_flow_id = flow_id.replace(":", "_").replace("->", "_to_")
        filename = f"{timestamp}_{safe_flow_id}.pcap"
        pcap_path = self.evidence_dir / filename

        # Convert packet dicts to Scapy packets and write
        if wrpcap is not None:
            scapy_packets = self._dicts_to_scapy(packets)
            if scapy_packets:
                wrpcap(str(pcap_path), scapy_packets)
                print(f"[Forensics] Captured {len(scapy_packets)} packets to {pcap_path}")

        # Store metadata
        capture = PacketCapture(
            flow_id=flow_id,
            timestamp=timestamp,
            packets=packets,
            pcap_path=str(pcap_path) if pcap_path.exists() else None
        )
        self.captured_flows[flow_id] = capture

        return str(pcap_path)

    def get_context_packets(self, flow: Dict, context_window: int = 50) -> List[dict]:
        """
        Get packets from ring buffer around the suspicious flow.
        Returns N packets before and after the flow.
        """
        flow_start = flow.get("start_time", 0)
        flow_end = flow.get("end_time", 0)

        # Find packets in time window
        context_packets = []
        for pkt in self.packet_buffer:
            pkt_time = pkt.get("timestamp", 0)
            if flow_start - 10 <= pkt_time <= flow_end + 10:
                context_packets.append(pkt)

        return context_packets[-context_window:] if len(context_packets) > context_window else context_packets

    def _dicts_to_scapy(self, packet_dicts: List[dict]) -> List:
        """Convert packet dictionaries to Scapy packets."""
        if not all([Ether, IP, TCP, UDP, ICMP]):
            return []

        scapy_packets = []
        for pkt_dict in packet_dicts:
            try:
                # Build IP layer
                ip = IP(
                    src=pkt_dict.get("src_ip", "0.0.0.0"),
                    dst=pkt_dict.get("dst_ip", "0.0.0.0")
                )

                # Build transport layer
                protocol = pkt_dict.get("protocol", "TCP")
                if protocol == "TCP":
                    transport = TCP(
                        sport=pkt_dict.get("src_port", 0),
                        dport=pkt_dict.get("dst_port", 0),
                        flags=pkt_dict.get("flags", ""),
                        window=pkt_dict.get("window_size", 0),
                        seq=pkt_dict.get("seq", 0),
                        ack=pkt_dict.get("ack", 0)
                    )
                elif protocol == "UDP":
                    transport = UDP(
                        sport=pkt_dict.get("src_port", 0),
                        dport=pkt_dict.get("dst_port", 0)
                    )
                elif protocol == "ICMP":
                    transport = ICMP(
                        type=pkt_dict.get("icmp_type", 8),
                        code=pkt_dict.get("icmp_code", 0)
                    )
                else:
                    continue

                # Combine layers
                packet = Ether() / ip / transport
                packet.time = pkt_dict.get("timestamp", time.time())
                scapy_packets.append(packet)

            except Exception as e:
                print(f"[Forensics] Failed to convert packet: {e}")
                continue

        return scapy_packets

    def generate_timeline(self, flow_id: str) -> Optional[Dict]:
        """Generate forensic timeline for a captured flow."""
        if flow_id not in self.captured_flows:
            return None

        capture = self.captured_flows[flow_id]
        packets = capture.packets

        if not packets:
            return None

        timeline = {
            "flow_id": flow_id,
            "start_time": min(p.get("timestamp", 0) for p in packets),
            "end_time": max(p.get("timestamp", 0) for p in packets),
            "packet_count": len(packets),
            "events": []
        }

        # Build event timeline
        for i, pkt in enumerate(packets):
            event = {
                "sequence": i + 1,
                "timestamp": pkt.get("timestamp", 0),
                "src": f"{pkt.get('src_ip')}:{pkt.get('src_port')}",
                "dst": f"{pkt.get('dst_ip')}:{pkt.get('dst_port')}",
                "protocol": pkt.get("protocol", ""),
                "size": pkt.get("size", 0),
            }

            # Add protocol-specific details
            if pkt.get("protocol") == "TCP":
                event["flags"] = pkt.get("flags", "")
            elif pkt.get("protocol") == "DNS":
                event["dns_query"] = pkt.get("dns_query", "")

            timeline["events"].append(event)

        return timeline

    def cleanup_old_evidence(self, max_age_days: int = 30):
        """Remove evidence files older than specified days."""
        cutoff = time.time() - (max_age_days * 86400)
        removed = 0

        for pcap_file in self.evidence_dir.glob("*.pcap"):
            if pcap_file.stat().st_mtime < cutoff:
                pcap_file.unlink()
                removed += 1

        print(f"[Forensics] Cleaned up {removed} old evidence files")
        return removed
