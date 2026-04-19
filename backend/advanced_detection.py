"""
Advanced covert channel detection techniques.
Detects IP ID steganography, TCP timestamp manipulation, and packet size encoding.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Dict, List, Tuple
import numpy as np


class AdvancedCovertChannelDetector:
    """Detects advanced covert channel techniques."""

    def __init__(self):
        self.ip_id_sequences = defaultdict(list)
        self.tcp_timestamp_sequences = defaultdict(list)
        self.packet_size_distributions = defaultdict(list)

    def analyze_ip_id_steganography(self, packets: List[dict]) -> Tuple[float, str]:
        """
        Detect IP ID field steganography.
        Normal: sequential or random. Covert: encoded data patterns.
        """
        if len(packets) < 10:
            return 0.0, ""

        ip_ids = [p.get("ip_id", 0) for p in packets if p.get("ip_id", 0) > 0]
        if len(ip_ids) < 10:
            return 0.0, ""

        # Calculate differences between consecutive IP IDs
        diffs = [ip_ids[i+1] - ip_ids[i] for i in range(len(ip_ids)-1)]
        
        # Normal traffic: mostly incremental (diff ~1) or random (high variance)
        # Covert: specific patterns, low variance but not sequential
        mean_diff = statistics.mean(diffs)
        std_diff = statistics.pstdev(diffs) if len(diffs) > 1 else 0

        score = 0.0
        reason = ""

        # Pattern 1: Non-sequential but low variance (encoded data)
        if 1 < abs(mean_diff) < 100 and std_diff < 50:
            score = 35.0
            reason = "IP ID: Non-sequential low-variance pattern - possible steganography"
        
        # Pattern 2: Repeating patterns
        elif len(set(diffs)) < len(diffs) * 0.3:
            score = 30.0
            reason = "IP ID: Repeating difference patterns - possible encoding"

        return score, reason

    def analyze_tcp_timestamp_manipulation(self, packets: List[dict]) -> Tuple[float, str]:
        """
        Detect TCP timestamp option manipulation.
        Normal: monotonically increasing. Covert: encoded in LSBs.
        """
        if len(packets) < 10:
            return 0.0, ""

        timestamps = [p.get("tcp_timestamp", 0) for p in packets if p.get("tcp_timestamp", 0) > 0]
        if len(timestamps) < 10:
            return 0.0, ""

        # Check LSB (least significant bits) for patterns
        lsbs = [ts & 0xFF for ts in timestamps]  # Last byte
        
        # Calculate entropy of LSBs
        lsb_entropy = self._calculate_entropy(lsbs)
        
        # Check if timestamps are monotonic
        is_monotonic = all(timestamps[i] <= timestamps[i+1] for i in range(len(timestamps)-1))

        score = 0.0
        reason = ""

        # High LSB entropy + monotonic = possible covert channel
        if lsb_entropy > 4.5 and is_monotonic:
            score = 40.0
            reason = "TCP Timestamp: High LSB entropy - possible data encoding"
        
        # Non-monotonic timestamps (unusual)
        elif not is_monotonic:
            score = 25.0
            reason = "TCP Timestamp: Non-monotonic values - suspicious"

        return score, reason

    def analyze_packet_size_encoding(self, packets: List[dict]) -> Tuple[float, str]:
        """
        Detect packet size-based covert channels.
        Analyzes frequency distribution for encoding patterns.
        """
        if len(packets) < 20:
            return 0.0, ""

        sizes = [p.get("size", 0) for p in packets]
        
        # Frequency analysis
        size_counts = defaultdict(int)
        for size in sizes:
            size_counts[size] += 1

        # Calculate metrics
        unique_sizes = len(size_counts)
        most_common_freq = max(size_counts.values())
        total = len(sizes)

        score = 0.0
        reason = ""

        # Pattern 1: Very few distinct sizes (possible alphabet encoding)
        if 3 <= unique_sizes <= 8 and total > 20:
            score = 35.0
            reason = f"Packet Size: Only {unique_sizes} distinct sizes - possible alphabet encoding"
        
        # Pattern 2: Bimodal distribution (two primary sizes)
        elif unique_sizes == 2 and total > 20:
            score = 40.0
            reason = "Packet Size: Binary size distribution - possible bit encoding"
        
        # Pattern 3: Uniform distribution across many sizes
        elif unique_sizes > 10 and most_common_freq < total * 0.15:
            score = 30.0
            reason = "Packet Size: Uniform distribution - possible data encoding"

        return score, reason

    def analyze_dns_tunneling(self, packets: List[dict]) -> Tuple[float, str]:
        """
        Detect DNS tunneling through subdomain analysis.
        """
        dns_queries = [p.get("dns_query", "") for p in packets if p.get("dns_query")]
        
        if len(dns_queries) < 5:
            return 0.0, ""

        # Calculate subdomain entropy
        subdomain_entropy = self._calculate_string_entropy(dns_queries)
        
        # Average query length
        avg_length = statistics.mean([len(q) for q in dns_queries])
        
        # Check for base64-like patterns
        base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        base64_ratio = sum(
            sum(1 for c in q if c in base64_chars) / len(q) if len(q) > 0 else 0
            for q in dns_queries
        ) / len(dns_queries)

        score = 0.0
        reason = ""

        # High entropy + long queries = tunneling
        if subdomain_entropy > 4.0 and avg_length > 40:
            score = 45.0
            reason = "DNS: High entropy long queries - DNS tunneling detected"
        
        # Base64-like encoding
        elif base64_ratio > 0.8 and avg_length > 30:
            score = 40.0
            reason = "DNS: Base64-encoded subdomains - DNS tunneling"
        
        # Many unique queries
        elif len(set(dns_queries)) / len(dns_queries) > 0.9:
            score = 35.0
            reason = "DNS: All unique queries - possible tunneling"

        return score, reason

    def _calculate_entropy(self, values: List[int]) -> float:
        """Calculate Shannon entropy of integer sequence."""
        if not values:
            return 0.0
        
        freq = defaultdict(int)
        for v in values:
            freq[v] += 1
        
        total = len(values)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy

    def _calculate_string_entropy(self, strings: List[str]) -> float:
        """Calculate Shannon entropy of character distribution."""
        if not strings:
            return 0.0
        
        combined = "".join(strings)
        if not combined:
            return 0.0
        
        freq = defaultdict(int)
        for char in combined:
            freq[char] += 1
        
        total = len(combined)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy

    def analyze_flow(self, packets: List[dict]) -> Dict:
        """
        Run all advanced detection techniques on a flow.
        Returns combined score and detected techniques.
        """
        results = {
            "ip_id_score": 0.0,
            "tcp_timestamp_score": 0.0,
            "packet_size_score": 0.0,
            "dns_tunneling_score": 0.0,
            "total_score": 0.0,
            "detected_techniques": []
        }

        # Run all detectors
        ip_score, ip_reason = self.analyze_ip_id_steganography(packets)
        ts_score, ts_reason = self.analyze_tcp_timestamp_manipulation(packets)
        ps_score, ps_reason = self.analyze_packet_size_encoding(packets)
        dns_score, dns_reason = self.analyze_dns_tunneling(packets)

        results["ip_id_score"] = ip_score
        results["tcp_timestamp_score"] = ts_score
        results["packet_size_score"] = ps_score
        results["dns_tunneling_score"] = dns_score

        # Combine scores (max to avoid over-penalizing)
        results["total_score"] = min(
            max(ip_score, ts_score, ps_score, dns_score),
            100.0
        )

        # Collect detected techniques
        if ip_reason:
            results["detected_techniques"].append(ip_reason)
        if ts_reason:
            results["detected_techniques"].append(ts_reason)
        if ps_reason:
            results["detected_techniques"].append(ps_reason)
        if dns_reason:
            results["detected_techniques"].append(dns_reason)

        return results
