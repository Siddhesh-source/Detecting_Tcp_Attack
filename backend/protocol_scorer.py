"""
Protocol-specific scoring rules for UDP, ICMP, and DNS covert channel detection.
"""

from typing import Dict, List, Tuple


def score_udp_flow(features: Dict) -> Tuple[float, List[str]]:
    """Score UDP flow for covert channel indicators."""
    points = 0
    reasons = []

    # Rule 1: Low IAT variance - periodic pattern
    std_iat = features.get("std_iat", 0)
    total_packets = features.get("total_packets", 0)
    if 0 < std_iat < 0.01 and total_packets > 10:
        points += 30
        reasons.append("UDP: Low IAT variance - periodic covert channel pattern")

    # Rule 2: Unusual packet size distribution
    mean_pkt = features.get("mean_pkt_size", 0)
    std_pkt = features.get("std_pkt_size", 0)
    if 0 < std_pkt < 10 and total_packets > 10:
        points += 25
        reasons.append("UDP: Uniform packet sizes - possible data encoding")

    # Rule 3: High packet rate to uncommon port
    pps = features.get("packets_per_sec", 0)
    dst_port = features.get("dst_port", 0)
    if pps > 10 and dst_port > 1024 and dst_port not in [53, 123, 161, 514]:
        points += 20
        reasons.append("UDP: High rate to non-standard port - suspicious")

    return (min(points, 100), reasons)


def score_icmp_flow(features: Dict) -> Tuple[float, List[str]]:
    """Score ICMP flow for covert channel indicators."""
    points = 0
    reasons = []

    # Rule 1: High payload entropy - data hiding
    payload_entropy = features.get("payload_entropy", 0)
    if payload_entropy > 5:
        points += 35
        reasons.append("ICMP: High payload entropy - possible data hiding")

    # Rule 2: Unusual echo request/reply ratio
    echo_req = features.get("echo_request_count", 0)
    echo_rep = features.get("echo_reply_count", 0)
    if echo_req > 0 and echo_rep == 0 and echo_req > 20:
        points += 30
        reasons.append("ICMP: One-way echo traffic - possible tunneling")

    # Rule 3: High packet rate
    total_packets = features.get("total_packets", 0)
    duration = features.get("duration", 1)
    if total_packets / duration > 5:
        points += 20
        reasons.append("ICMP: High packet rate - unusual for ICMP")

    # Rule 4: Type diversity (multiple ICMP types)
    type_diversity = features.get("icmp_type_diversity", 0)
    if type_diversity > 3:
        points += 15
        reasons.append("ICMP: Multiple message types - suspicious pattern")

    return (min(points, 100), reasons)


def score_dns_flow(features: Dict) -> Tuple[float, List[str]]:
    """Score DNS flow for tunneling indicators."""
    points = 0
    reasons = []

    # Rule 1: High subdomain entropy - DGA or tunneling
    subdomain_entropy = features.get("subdomain_entropy", 0)
    if subdomain_entropy > 3.5:
        points += 40
        reasons.append("DNS: High subdomain entropy - possible tunneling/DGA")

    # Rule 2: Long subdomain length
    avg_subdomain_len = features.get("avg_subdomain_length", 0)
    if avg_subdomain_len > 40:
        points += 30
        reasons.append("DNS: Long subdomain names - DNS tunneling indicator")

    # Rule 3: High query rate
    query_count = features.get("query_count", 0)
    duration = features.get("duration", 1)
    if query_count / duration > 10:
        points += 20
        reasons.append("DNS: High query rate - suspicious")

    # Rule 4: TXT record abuse
    txt_count = features.get("txt_record_count", 0)
    if txt_count > 5:
        points += 25
        reasons.append("DNS: Multiple TXT queries - common in DNS tunneling")

    # Rule 5: Unusual query/response ratio
    qr_ratio = features.get("query_response_ratio", 1)
    if qr_ratio > 3:
        points += 15
        reasons.append("DNS: High query/response ratio - possible failed tunneling")

    return (min(points, 100), reasons)
