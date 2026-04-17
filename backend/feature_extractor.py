"""
Feature extractor – transforms a Flow object into a flat feature dict.

Each feature group is annotated with its corresponding OSI layer so that
the scorer and frontend can attribute alerts to the correct layer.

Output dict includes a "feature_layer_map" field that maps every feature
name to its OSI layer: "Network", "Transport", or "Derived".
"""

from __future__ import annotations

import statistics
from typing import Dict, List


# ===========================================================================
# Feature → OSI layer mapping  (used by scorer & frontend)
# ===========================================================================
FEATURE_LAYER_MAP: Dict[str, str] = {
    # OSI LAYER 3 (Network) - IP-level metadata
    "src_ip":           "Network",
    "dst_ip":           "Network",
    "src_port":         "Network",
    "dst_port":         "Network",
    "protocol":         "Network",
    "flow_id":          "Network",
    # OSI LAYER 4 (Transport) - TCP behavior
    "syn_count":        "Transport",
    "ack_count":        "Transport",
    "fin_count":        "Transport",
    "rst_count":        "Transport",
    "retransmit_count": "Transport",
    "avg_window_size":  "Transport",
    "tcp_layer":        "Transport",
    # DERIVED - Computed timing/statistical features
    "start_time":       "Derived",
    "end_time":         "Derived",
    "duration":         "Derived",
    "total_packets":    "Derived",
    "total_bytes":      "Derived",
    "mean_pkt_size":    "Derived",
    "std_pkt_size":     "Derived",
    "min_pkt_size":     "Derived",
    "max_pkt_size":     "Derived",
    "packets_per_sec":  "Derived",
    "bytes_per_sec":    "Derived",
    "mean_iat":         "Derived",
    "std_iat":          "Derived",
    "min_iat":          "Derived",
    "max_iat":          "Derived",
    "burst_count":      "Derived",
    "fwd_packets":      "Derived",
    "bwd_packets":      "Derived",
    "fwd_bwd_ratio":    "Derived",
}


def extract_features(flow) -> Dict:
    """
    Given a Flow dataclass (from flow_builder), compute all statistical
    features and return a dict ready for scoring / ML / DB insertion.

    Returns a dict with ALL features below plus "feature_layer_map".
    """
    pkts: List[dict] = flow.packets
    key = flow.key
    n = len(pkts)
    if n == 0:
        result = _empty_flow(key, flow)
        result["feature_layer_map"] = dict(FEATURE_LAYER_MAP)
        return result

    # ==================================================================
    # OSI LAYER 3 (Network) - IP-level metadata
    # ==================================================================
    flow_id = f"{key[0]}:{key[2]}->{key[1]}:{key[3]}"
    src_ip = key[0]
    dst_ip = key[1]
    src_port = key[2]
    dst_port = key[3]
    protocol = key[4]

    # ==================================================================
    # OSI LAYER 4 (Transport) - TCP behavior
    # ==================================================================

    # --- TCP flag counts -------------------------------------------------
    syn_count = sum(1 for p in pkts if "S" in p.get("flags", ""))
    ack_count = sum(1 for p in pkts if "A" in p.get("flags", ""))
    fin_count = sum(1 for p in pkts if "F" in p.get("flags", ""))
    rst_count = sum(1 for p in pkts if "R" in p.get("flags", ""))

    # --- Retransmit heuristic (repeated seq numbers) --------------------
    seqs = [p["seq"] for p in pkts]
    retransmit_count = 0
    seen_seqs = set()
    for s in seqs:
        if s in seen_seqs:
            retransmit_count += 1
        seen_seqs.add(s)

    # --- Average TCP window size (flow control field) --------------------
    windows = [p["window_size"] for p in pkts]
    avg_window_size = statistics.mean(windows) if windows else 0.0

    # --- Transport layer tag ---------------------------------------------
    tcp_layer = "Transport"

    # ==================================================================
    # DERIVED - Computed timing/statistical features
    # ==================================================================

    # --- Duration --------------------------------------------------------
    start_time = flow.start_time
    end_time = flow.last_time
    duration = end_time - start_time

    # --- Packet sizes ----------------------------------------------------
    sizes = [p["size"] for p in pkts]
    total_packets = n
    total_bytes = sum(sizes)
    mean_pkt_size = statistics.mean(sizes)
    std_pkt_size = statistics.pstdev(sizes) if n > 1 else 0.0
    min_pkt_size = min(sizes)
    max_pkt_size = max(sizes)

    # --- Rates -----------------------------------------------------------
    packets_per_sec = total_packets / duration if duration > 0 else 0.0
    bytes_per_sec = total_bytes / duration if duration > 0 else 0.0

    # --- Inter-arrival times ---------------------------------------------
    timestamps = sorted(p["timestamp"] for p in pkts)
    iats = (
        [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        if n > 1
        else [0.0]
    )
    mean_iat = statistics.mean(iats)
    std_iat = statistics.pstdev(iats) if len(iats) > 1 else 0.0
    min_iat = min(iats)
    max_iat = max(iats)

    # --- Burst detection (IAT < 0.01s) -----------------------------------
    burst_count = 0
    in_burst = False
    for iat in iats:
        if iat < 0.01:
            if not in_burst:
                burst_count += 1
                in_burst = True
        else:
            in_burst = False

    # --- Forward / backward split ----------------------------------------
    # "Forward" = packets whose src matches the flow's first packet's src
    first_src_ip = pkts[0]["src_ip"]
    first_src_port = pkts[0]["src_port"]
    fwd_packets = sum(
        1 for p in pkts
        if p["src_ip"] == first_src_ip and p["src_port"] == first_src_port
    )
    bwd_packets = n - fwd_packets
    fwd_bwd_ratio = fwd_packets / bwd_packets if bwd_packets > 0 else float(fwd_packets)

    # ==================================================================
    # Assemble result
    # ==================================================================
    result = {
        # OSI LAYER 3 (Network) - IP-level metadata
        "flow_id":   flow_id,
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "src_port":  src_port,
        "dst_port":  dst_port,
        "protocol":  protocol,

        # OSI LAYER 4 (Transport) - TCP behavior
        "syn_count":        syn_count,
        "ack_count":        ack_count,
        "fin_count":        fin_count,
        "rst_count":        rst_count,
        "retransmit_count": retransmit_count,
        "avg_window_size":  round(avg_window_size, 2),
        "tcp_layer":        tcp_layer,

        # DERIVED - Computed timing/statistical features
        "start_time":       start_time,
        "end_time":         end_time,
        "duration":         duration,
        "total_packets":    total_packets,
        "total_bytes":      total_bytes,
        "mean_pkt_size":    round(mean_pkt_size, 4),
        "std_pkt_size":     round(std_pkt_size, 4),
        "min_pkt_size":     min_pkt_size,
        "max_pkt_size":     max_pkt_size,
        "packets_per_sec":  round(packets_per_sec, 4),
        "bytes_per_sec":    round(bytes_per_sec, 4),
        "mean_iat":         round(mean_iat, 6),
        "std_iat":          round(std_iat, 6),
        "min_iat":          round(min_iat, 6),
        "max_iat":          round(max_iat, 6),
        "burst_count":      burst_count,
        "fwd_packets":      fwd_packets,
        "bwd_packets":      bwd_packets,
        "fwd_bwd_ratio":    round(fwd_bwd_ratio, 4),

        # Layer mapping for frontend / scorer
        "feature_layer_map": dict(FEATURE_LAYER_MAP),
    }
    return result


def _empty_flow(key, flow) -> Dict:
    """Return a zero-filled feature dict for an empty flow."""
    return {
        # OSI LAYER 3 (Network)
        "flow_id":   f"{key[0]}:{key[2]}->{key[1]}:{key[3]}",
        "src_ip":    key[0],
        "dst_ip":    key[1],
        "src_port":  key[2],
        "dst_port":  key[3],
        "protocol":  key[4],
        # OSI LAYER 4 (Transport)
        "syn_count":        0,
        "ack_count":        0,
        "fin_count":        0,
        "rst_count":        0,
        "retransmit_count": 0,
        "avg_window_size":  0.0,
        "tcp_layer":        "Transport",
        # DERIVED
        "start_time":       flow.start_time,
        "end_time":         flow.last_time,
        "duration":         0.0,
        "total_packets":    0,
        "total_bytes":      0,
        "mean_pkt_size":    0.0,
        "std_pkt_size":     0.0,
        "min_pkt_size":     0,
        "max_pkt_size":     0,
        "packets_per_sec":  0.0,
        "bytes_per_sec":    0.0,
        "mean_iat":         0.0,
        "std_iat":          0.0,
        "min_iat":          0.0,
        "max_iat":          0.0,
        "burst_count":      0,
        "fwd_packets":      0,
        "bwd_packets":      0,
        "fwd_bwd_ratio":    0.0,
    }
