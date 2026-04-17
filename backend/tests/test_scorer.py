"""Unit tests for the rule-based scorer."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scorer import compute_suspicion


def test_benign_flow_zero_score():
    """A typical benign flow should score 0."""
    features = {
        "std_iat": 0.5,
        "total_packets": 20,
        "duration": 5.0,
        "packets_per_sec": 4.0,
        "mean_pkt_size": 500,
        "fwd_bwd_ratio": 1.2,
        "burst_count": 2,
        "retransmit_count": 0,
    }
    score, reasons = compute_suspicion(features)
    assert score == 0
    assert reasons == []


def test_timing_channel_detected():
    """Low IAT variance + enough packets → timing channel rule fires."""
    features = {
        "std_iat": 0.005,
        "total_packets": 50,
        "duration": 10.0,
        "packets_per_sec": 5.0,
        "mean_pkt_size": 500,
        "fwd_bwd_ratio": 1.0,
        "burst_count": 2,
        "retransmit_count": 0,
    }
    score, reasons = compute_suspicion(features)
    assert score >= 30
    assert any("IAT" in r for r in reasons)


def test_exfiltration_detected():
    """High fwd/bwd ratio → exfiltration rule fires."""
    features = {
        "std_iat": 0.5,
        "total_packets": 20,
        "duration": 5.0,
        "packets_per_sec": 4.0,
        "mean_pkt_size": 500,
        "fwd_bwd_ratio": 10.0,
        "burst_count": 1,
        "retransmit_count": 0,
    }
    score, reasons = compute_suspicion(features)
    assert score >= 25
    assert any("exfiltration" in r.lower() for r in reasons)


def test_covert_persistence_detected():
    """Long-duration + low-rate → covert persistence rule fires."""
    features = {
        "std_iat": 0.5,
        "total_packets": 5,
        "duration": 120.0,
        "packets_per_sec": 0.04,
        "mean_pkt_size": 500,
        "fwd_bwd_ratio": 1.0,
        "burst_count": 0,
        "retransmit_count": 0,
    }
    score, reasons = compute_suspicion(features)
    assert score >= 25
    assert any("persistence" in r.lower() for r in reasons)


def test_score_capped_at_100():
    """Even if all rules fire, score must not exceed 100."""
    features = {
        "std_iat": 0.005,
        "total_packets": 200,
        "duration": 300.0,
        "packets_per_sec": 0.3,
        "mean_pkt_size": 50,
        "fwd_bwd_ratio": 20.0,
        "burst_count": 180,
        "retransmit_count": 50,
    }
    score, reasons = compute_suspicion(features)
    assert score == 100
