"""
Behavioral baselining for per-IP/subnet normal traffic profiling.
Implements time-series anomaly detection and circadian rhythm analysis.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import statistics
import numpy as np


@dataclass
class TrafficProfile:
    """Traffic profile for an IP or subnet."""
    ip: str
    flow_count: int = 0
    total_bytes: int = 0
    total_packets: int = 0
    avg_duration: float = 0.0
    avg_packets_per_sec: float = 0.0
    protocols: Dict[str, int] = field(default_factory=dict)
    ports: Dict[int, int] = field(default_factory=dict)
    hourly_activity: List[int] = field(default_factory=lambda: [0] * 24)
    last_updated: float = field(default_factory=time.time)


class BehavioralBaseline:
    """Behavioral baselining engine for anomaly detection."""

    def __init__(self, learning_period: int = 86400):  # 24 hours
        self.learning_period = learning_period
        self.profiles: Dict[str, TrafficProfile] = {}
        self.subnet_profiles: Dict[str, TrafficProfile] = {}
        self.baseline_established = False
        self.start_time = time.time()

    def update_profile(self, flow: Dict):
        """Update traffic profile for source IP."""
        src_ip = flow.get("src_ip", "")
        if not src_ip:
            return

        # Update IP profile
        if src_ip not in self.profiles:
            self.profiles[src_ip] = TrafficProfile(ip=src_ip)

        profile = self.profiles[src_ip]
        profile.flow_count += 1
        profile.total_bytes += flow.get("total_bytes", 0)
        profile.total_packets += flow.get("total_packets", 0)
        
        # Update averages
        profile.avg_duration = (
            (profile.avg_duration * (profile.flow_count - 1) + flow.get("duration", 0))
            / profile.flow_count
        )
        profile.avg_packets_per_sec = (
            (profile.avg_packets_per_sec * (profile.flow_count - 1) + flow.get("packets_per_sec", 0))
            / profile.flow_count
        )

        # Protocol distribution
        protocol = flow.get("protocol", "TCP")
        profile.protocols[protocol] = profile.protocols.get(protocol, 0) + 1

        # Port distribution
        dst_port = flow.get("dst_port", 0)
        profile.ports[dst_port] = profile.ports.get(dst_port, 0) + 1

        # Hourly activity (circadian rhythm)
        hour = time.localtime(flow.get("created_at", time.time())).tm_hour
        profile.hourly_activity[hour] += 1
        profile.last_updated = time.time()

        # Update subnet profile
        subnet = self._get_subnet(src_ip)
        if subnet not in self.subnet_profiles:
            self.subnet_profiles[subnet] = TrafficProfile(ip=subnet)
        
        subnet_profile = self.subnet_profiles[subnet]
        subnet_profile.flow_count += 1
        subnet_profile.total_bytes += flow.get("total_bytes", 0)

        # Check if baseline period complete
        if not self.baseline_established and (time.time() - self.start_time) > self.learning_period:
            self.baseline_established = True
            print(f"[Baseline] Learning period complete. {len(self.profiles)} IP profiles established.")

    def detect_anomaly(self, flow: Dict) -> Dict:
        """Detect if flow deviates from established baseline."""
        if not self.baseline_established:
            return {"is_anomaly": False, "reason": "Baseline learning in progress"}

        src_ip = flow.get("src_ip", "")
        if src_ip not in self.profiles:
            return {
                "is_anomaly": True,
                "anomaly_score": 30.0,
                "reason": "New IP - no baseline profile",
                "anomaly_type": "new_entity"
            }

        profile = self.profiles[src_ip]
        anomalies = []
        score = 0.0

        # Check protocol deviation
        protocol = flow.get("protocol", "TCP")
        if protocol not in profile.protocols:
            anomalies.append(f"Unusual protocol: {protocol}")
            score += 20.0

        # Check port deviation
        dst_port = flow.get("dst_port", 0)
        if dst_port not in profile.ports and dst_port > 1024:
            anomalies.append(f"New destination port: {dst_port}")
            score += 15.0

        # Check traffic volume deviation
        avg_bytes = profile.total_bytes / profile.flow_count if profile.flow_count > 0 else 0
        flow_bytes = flow.get("total_bytes", 0)
        if avg_bytes > 0 and flow_bytes > avg_bytes * 5:
            anomalies.append(f"Traffic volume 5x above baseline")
            score += 25.0

        # Check packet rate deviation
        flow_pps = flow.get("packets_per_sec", 0)
        if profile.avg_packets_per_sec > 0 and flow_pps > profile.avg_packets_per_sec * 3:
            anomalies.append(f"Packet rate 3x above baseline")
            score += 20.0

        # Circadian rhythm check
        hour = time.localtime(flow.get("created_at", time.time())).tm_hour
        avg_hourly = statistics.mean(profile.hourly_activity) if profile.hourly_activity else 0
        if avg_hourly > 0 and profile.hourly_activity[hour] < avg_hourly * 0.1:
            anomalies.append(f"Off-hours activity (hour {hour})")
            score += 20.0

        return {
            "is_anomaly": score > 30,
            "anomaly_score": min(score, 100.0),
            "reason": "; ".join(anomalies) if anomalies else "Within baseline",
            "anomaly_type": "behavioral_deviation" if anomalies else None
        }

    def get_circadian_pattern(self, ip: str) -> Optional[List[int]]:
        """Get hourly activity pattern for IP."""
        if ip in self.profiles:
            return self.profiles[ip].hourly_activity
        return None

    def _get_subnet(self, ip: str) -> str:
        """Extract /24 subnet from IP."""
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ip

    def get_profile_stats(self) -> Dict:
        """Get baseline statistics."""
        return {
            "total_profiles": len(self.profiles),
            "total_subnets": len(self.subnet_profiles),
            "baseline_established": self.baseline_established,
            "learning_progress": min(
                (time.time() - self.start_time) / self.learning_period * 100, 100
            ),
            "top_active_ips": sorted(
                [(ip, p.flow_count) for ip, p in self.profiles.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }
