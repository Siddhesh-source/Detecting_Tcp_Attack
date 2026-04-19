"""
Generate synthetic flow data for testing the dashboard.
"""
import asyncio
import random
import time
from database import init_db, insert_flow

async def generate_test_flows(count=50):
    """Generate synthetic flows for testing."""
    await init_db()
    
    protocols = ["TCP", "UDP", "ICMP", "DNS"]
    ips = [f"192.168.1.{i}" for i in range(10, 50)]
    
    for i in range(count):
        src_ip = random.choice(ips)
        dst_ip = random.choice(ips)
        protocol = random.choice(protocols)
        
        # Generate realistic features
        duration = random.uniform(0.1, 120)
        total_packets = random.randint(5, 500)
        total_bytes = random.randint(500, 50000)
        mean_pkt_size = total_bytes / total_packets
        std_pkt_size = random.uniform(10, 200)
        packets_per_sec = total_packets / duration
        bytes_per_sec = total_bytes / duration
        mean_iat = duration / total_packets
        std_iat = random.uniform(0.0001, 0.1)
        
        # Generate realistic suspicion score and reasons
        suspicion_score = random.uniform(0, 100)
        is_anomaly = 1 if suspicion_score >= 50 else 0
        
        # Generate believable alert reasons based on flow characteristics
        reasons = []
        if is_anomaly:
            if std_iat < 0.01 and total_packets > 10:
                reasons.append("Transport/Derived: Low IAT variance - periodic covert channel pattern")
            if duration > 60 and packets_per_sec < 0.5:
                reasons.append("Derived: Long-duration low-rate flow - covert persistence indicator")
            if mean_pkt_size < 100 and total_packets > 10:
                reasons.append("Network/Transport: Small packet dominance - possible data encoding")
            if random.random() > 0.5:
                reasons.append("Derived: Asymmetric flow - possible data exfiltration")
            if random.random() > 0.6:
                reasons.append("Transport: High retransmission rate - possible channel manipulation")
            if not reasons:
                reasons.append("Derived: Anomalous traffic pattern detected")
        
        alert_reasons = "; ".join(reasons) if reasons else ""
        
        flow = {
            "flow_id": f"{src_ip}:{random.randint(1024,65535)}->{dst_ip}:{random.randint(80,443)}",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 53, 22, 3389]),
            "protocol": protocol,
            "start_time": time.time() - random.uniform(0, 3600),
            "end_time": time.time(),
            "duration": duration,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "mean_pkt_size": mean_pkt_size,
            "std_pkt_size": std_pkt_size,
            "min_pkt_size": int(mean_pkt_size * 0.5),
            "max_pkt_size": int(mean_pkt_size * 1.5),
            "packets_per_sec": packets_per_sec,
            "bytes_per_sec": bytes_per_sec,
            "mean_iat": mean_iat,
            "std_iat": std_iat,
            "min_iat": mean_iat * 0.1,
            "max_iat": mean_iat * 2,
            "burst_count": random.randint(0, 10),
            "syn_count": random.randint(1, 5),
            "ack_count": random.randint(5, 50),
            "fin_count": random.randint(0, 2),
            "rst_count": random.randint(0, 1),
            "retransmit_count": random.randint(0, 5),
            "avg_window_size": random.randint(8192, 65535),
            "fwd_packets": int(total_packets * 0.6),
            "bwd_packets": int(total_packets * 0.4),
            "fwd_bwd_ratio": random.uniform(0.5, 5),
            "suspicion_score": suspicion_score,
            "alert_reasons": alert_reasons,
            "is_anomaly": is_anomaly,
            "predicted_label": "ATTACK" if is_anomaly else "BENIGN",
            "true_label": "UNKNOWN",
            "created_at": time.time(),
            "tcp_layer": "Transport"
        }
        
        await insert_flow(flow)
        print(f"Generated flow {i+1}/{count}: {flow['flow_id']} (score: {suspicion_score:.1f})")

if __name__ == "__main__":
    asyncio.run(generate_test_flows(50))
    print("\nTest data generated successfully!")
