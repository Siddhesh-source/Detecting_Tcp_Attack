"""
FlowBuilder - groups individual packets into bidirectional TCP flows.

A flow is identified by the 5-tuple
    (src_ip, dst_ip, src_port, dst_port, protocol)

Packets arriving in either direction of the same 5-tuple are merged
into one flow object.  Flows idle for more than *timeout* seconds
are returned by get_completed_flows() and removed from the active set.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

FlowKey = Tuple[str, str, int, int, str]


@dataclass
class Flow:
    key: FlowKey
    packets: List[dict] = field(default_factory=list)
    start_time: float = float("inf")
    last_time: float = 0.0


class FlowBuilder:
    """Accumulate packets into flows and expire idle ones."""

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self.active: Dict[FlowKey, Flow] = {}

    # ------------------------------------------------------------------
    def _normalize_key(self, pkt: dict) -> FlowKey:
        """
        Normalize so that packets in both directions land in the same flow.
        Sort the IP+port pairs so (A->B) and (B->A) share a key.
        """
        a = (pkt["src_ip"], pkt["src_port"])
        b = (pkt["dst_ip"], pkt["dst_port"])
        if a <= b:
            return (a[0], b[0], a[1], b[1], pkt["protocol"])
        else:
            return (b[0], a[0], b[1], a[1], pkt["protocol"])

    # ------------------------------------------------------------------
    def add_packet(self, pkt: dict) -> Flow:
        """Add a packet dict to the appropriate flow (creates if new)."""
        key = self._normalize_key(pkt)
        if key not in self.active:
            self.active[key] = Flow(key=key)
        flow = self.active[key]
        flow.packets.append(pkt)
        flow.start_time = min(flow.start_time, pkt["timestamp"])
        flow.last_time = max(flow.last_time, pkt["timestamp"])
        return flow

    # ------------------------------------------------------------------
    def get_completed_flows(self, timeout: float | None = None) -> List[Flow]:
        """
        Return and remove all flows that have been idle for more than
        *timeout* seconds (default: self.timeout).
        """
        t = timeout if timeout is not None else self.timeout
        now = time.time()
        completed = []
        expired_keys = []
        for key, flow in self.active.items():
            if now - flow.last_time > t:
                completed.append(flow)
                expired_keys.append(key)
        for key in expired_keys:
            del self.active[key]
        return completed

    # ------------------------------------------------------------------
    def get_all_flows(self) -> List[Flow]:
        """Return all currently active flows (does NOT remove them)."""
        return list(self.active.values())
