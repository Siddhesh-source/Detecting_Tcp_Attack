"""
Scorer – points-based suspicion scoring with OSI-layer tags.

compute_suspicion(features_dict) -> (score, reasons)

Each rule adds a fixed number of points (capped at 100) and tags the
reason string with the OSI layer(s) involved.  The final score is the
sum of all triggered rules, normalized to 0–100.

Rules are aligned with covert-channel literature:
  - Low IAT variance      → timing channel
  - Long + low-rate        → stealthy persistence
  - Small packets         → header-field encoding
  - Asymmetric flow       → data exfiltration
  - High burst ratio      → bursty-silent covert pattern
  - High retransmit rate  → channel manipulation
"""

from __future__ import annotations
from typing import Dict, List, Tuple


def compute_suspicion(features: Dict) -> Tuple[float, List[str]]:
    """
    Returns (score, reasons).
      score   : 0.0 – 100.0  (capped)
      reasons : list of human-readable strings with OSI layer tags
    """
    points = 0
    reasons: List[str] = []

    # ---- Rule 1: Low IAT std — periodic covert channel pattern -----------
    std_iat = features.get("std_iat", 0)
    total_packets = features.get("total_packets", 0)
    if 0 < std_iat < 0.01 and total_packets > 10:
        points += 30
        reasons.append(
            "Transport/Derived: Low IAT variance — periodic covert channel pattern"
        )

    # ---- Rule 2: Long duration + low packet rate — covert persistence -----
    duration = features.get("duration", 0)
    pps = features.get("packets_per_sec", 0)
    if duration > 60 and pps < 0.5:
        points += 25
        reasons.append(
            "Derived: Long-duration low-rate flow — covert persistence indicator"
        )

    # ---- Rule 3: Small mean packet size — possible data encoding ---------
    mean_pkt = features.get("mean_pkt_size", 0)
    if 0 < mean_pkt < 100 and total_packets > 10:
        points += 20
        reasons.append(
            "Network/Transport: Small packet dominance — possible data encoding"
        )

    # ---- Rule 4: High fwd/bwd ratio — possible data exfiltration ----------
    ratio = features.get("fwd_bwd_ratio", 0)
    if ratio > 5:
        points += 25
        reasons.append(
            "Derived: Asymmetric flow — possible data exfiltration"
        )

    # ---- Rule 5: High burst ratio — bursty-silent covert pattern ---------
    burst_count = features.get("burst_count", 0)
    if total_packets > 0 and burst_count > total_packets * 0.8:
        points += 15
        reasons.append(
            "Derived: High burst ratio — bursty-silent covert pattern"
        )

    # ---- Rule 6: High retransmission rate — channel manipulation ----------
    retrans = features.get("retransmit_count", 0)
    if total_packets > 0 and retrans > total_packets * 0.1:
        points += 10
        reasons.append(
            "Transport: High retransmission rate — possible channel manipulation"
        )

    # ---- Cap at 100 ------------------------------------------------------
    score = min(points, 100)
    return (float(score), reasons)
