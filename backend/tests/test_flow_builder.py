"""Unit tests for the FlowBuilder."""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flow_builder import FlowBuilder


def _make_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=12345, dst_port=80, **extra):
    pkt = {
        "timestamp": time.time(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": "TCP",
        "size": 100,
        "flags": "S",
        "window_size": 65535,
        "seq": 1000,
        "ack": 0,
    }
    pkt.update(extra)
    return pkt


def test_single_packet_creates_flow():
    fb = FlowBuilder(timeout=999)
    fb.add_packet(_make_packet())
    flows = fb.get_all_flows()
    assert len(flows) == 1
    assert len(flows[0].packets) == 1


def test_bidirectional_same_flow():
    fb = FlowBuilder(timeout=999)
    fb.add_packet(_make_packet(src_ip="A", dst_ip="B", src_port=1, dst_port=2))
    fb.add_packet(_make_packet(src_ip="B", dst_ip="A", src_port=2, dst_port=1))
    flows = fb.get_all_flows()
    assert len(flows) == 1
    assert len(flows[0].packets) == 2


def test_different_tuples_different_flows():
    fb = FlowBuilder(timeout=999)
    fb.add_packet(_make_packet(src_ip="A", dst_ip="B", src_port=1, dst_port=80))
    fb.add_packet(_make_packet(src_ip="A", dst_ip="B", src_port=1, dst_port=443))
    flows = fb.get_all_flows()
    assert len(flows) == 2
