"""
Protocol-specific handlers for UDP, ICMP, and DNS packet processing.
Extends capture beyond TCP to detect covert channels across multiple protocols.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Dict, List, Optional

try:
    from scapy.all import DNS, ICMP, IP, UDP
except ImportError:
    DNS = ICMP = IP = UDP = None


class UDPFlowHandler:
    """Extract features from UDP flows for covert channel detection."""

    @staticmethod
    def extract_features(packets: List[dict]) -> Dict:
        if not packets:
            return {}

        sizes = [p["size"] for p in packets]
        timestamps = sorted(p["timestamp"] for p in packets)
        iats = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)] if len(timestamps) > 1 else [0.0]

        return {
            "protocol": "UDP",
            "total_packets": len(packets),
            "total_bytes": sum(sizes),
            "mean_pkt_size": statistics.mean(sizes),
            "std_pkt_size": statistics.pstdev(sizes) if len(sizes) > 1 else 0.0,
            "mean_iat": statistics.mean(iats),
            "std_iat": statistics.pstdev(iats) if len(iats) > 1 else 0.0,
            "duration": timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.0,
            "packets_per_sec": len(packets) / (timestamps[-1] - timestamps[0]) if len(timestamps) > 1 and timestamps[-1] > timestamps[0] else 0.0,
        }


class ICMPFlowHandler:
    """Extract features from ICMP flows for covert channel detection."""

    @staticmethod
    def extract_features(packets: List[dict]) -> Dict:
        if not packets:
            return {}

        sizes = [p["size"] for p in packets]
        timestamps = sorted(p["timestamp"] for p in packets)
        iats = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)] if len(timestamps) > 1 else [0.0]

        # ICMP-specific: type/code analysis
        type_counts = defaultdict(int)
        for p in packets:
            icmp_type = p.get("icmp_type", -1)
            type_counts[icmp_type] += 1

        # Payload size variance (common in ICMP tunneling)
        payload_sizes = [p.get("payload_size", 0) for p in packets]
        payload_entropy = statistics.pstdev(payload_sizes) if len(payload_sizes) > 1 else 0.0

        return {
            "protocol": "ICMP",
            "total_packets": len(packets),
            "total_bytes": sum(sizes),
            "mean_pkt_size": statistics.mean(sizes),
            "std_pkt_size": statistics.pstdev(sizes) if len(sizes) > 1 else 0.0,
            "mean_iat": statistics.mean(iats),
            "std_iat": statistics.pstdev(iats) if len(iats) > 1 else 0.0,
            "duration": timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.0,
            "icmp_type_diversity": len(type_counts),
            "payload_entropy": payload_entropy,
            "echo_request_count": type_counts.get(8, 0),
            "echo_reply_count": type_counts.get(0, 0),
        }


class DNSFlowHandler:
    """Extract features from DNS flows for tunneling detection."""

    @staticmethod
    def extract_features(packets: List[dict]) -> Dict:
        if not packets:
            return {}

        sizes = [p["size"] for p in packets]
        timestamps = sorted(p["timestamp"] for p in packets)
        iats = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)] if len(timestamps) > 1 else [0.0]

        # DNS-specific features
        query_count = sum(1 for p in packets if p.get("dns_qr") == 0)
        response_count = sum(1 for p in packets if p.get("dns_qr") == 1)
        
        # Subdomain analysis
        subdomains = [p.get("dns_query", "") for p in packets if p.get("dns_query")]
        avg_subdomain_length = statistics.mean([len(s) for s in subdomains]) if subdomains else 0.0
        
        # Entropy calculation for subdomain randomness
        subdomain_entropy = DNSFlowHandler._calculate_entropy(subdomains)
        
        # TXT record count (common in DNS tunneling)
        txt_record_count = sum(1 for p in packets if p.get("dns_qtype") == 16)

        return {
            "protocol": "DNS",
            "total_packets": len(packets),
            "total_bytes": sum(sizes),
            "mean_pkt_size": statistics.mean(sizes),
            "std_pkt_size": statistics.pstdev(sizes) if len(sizes) > 1 else 0.0,
            "mean_iat": statistics.mean(iats),
            "std_iat": statistics.pstdev(iats) if len(iats) > 1 else 0.0,
            "duration": timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.0,
            "query_count": query_count,
            "response_count": response_count,
            "query_response_ratio": query_count / response_count if response_count > 0 else float(query_count),
            "avg_subdomain_length": avg_subdomain_length,
            "subdomain_entropy": subdomain_entropy,
            "txt_record_count": txt_record_count,
        }

    @staticmethod
    def _calculate_entropy(strings: List[str]) -> float:
        """Calculate Shannon entropy of character distribution in strings."""
        if not strings:
            return 0.0
        
        combined = "".join(strings)
        if not combined:
            return 0.0
        
        freq = defaultdict(int)
        for char in combined:
            freq[char] += 1
        
        length = len(combined)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * (p ** 0.5)  # Simplified entropy
        
        return entropy


def packet_to_dict(pkt) -> Optional[dict]:
    """Convert Scapy packet to dict for any protocol (TCP/UDP/ICMP/DNS)."""
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    base = {
        "timestamp": float(pkt.time),
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "size": len(pkt),
    }

    # TCP
    if pkt.haslayer("TCP"):
        from scapy.all import TCP
        tcp = pkt[TCP]
        return {
            **base,
            "src_port": int(tcp.sport),
            "dst_port": int(tcp.dport),
            "protocol": "TCP",
            "flags": str(tcp.flags),
            "window_size": int(tcp.window),
            "seq": int(tcp.seq),
            "ack": int(tcp.ack),
            "tcp_layer": "Transport",
        }

    # UDP
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        result = {
            **base,
            "src_port": int(udp.sport),
            "dst_port": int(udp.dport),
            "protocol": "UDP",
        }
        
        # Check for DNS
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            result.update({
                "protocol": "DNS",
                "dns_qr": int(dns.qr),
                "dns_query": dns.qd.qname.decode() if dns.qd else "",
                "dns_qtype": int(dns.qd.qtype) if dns.qd else 0,
            })
        
        return result

    # ICMP
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        payload_size = len(bytes(icmp.payload)) if icmp.payload else 0
        return {
            **base,
            "src_port": 0,
            "dst_port": 0,
            "protocol": "ICMP",
            "icmp_type": int(icmp.type),
            "icmp_code": int(icmp.code),
            "payload_size": payload_size,
        }

    return None
