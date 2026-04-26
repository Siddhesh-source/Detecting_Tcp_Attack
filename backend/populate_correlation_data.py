"""
Populate cross-flow correlation data for testing.
"""
import asyncio
import random
import time
from database import init_db, insert_correlation, insert_coordinated_attack

CORRELATION_TYPES = ["timing_pattern", "payload_similarity", "protocol_sequence", "multi_protocol"]
IPS = ["192.168.1.10", "192.168.1.20", "10.0.0.5", "172.16.0.100", "192.168.1.50"]
PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS"]

async def populate_correlation_data(corr_count=30, attack_count=5):
    """Generate and insert sample correlations and coordinated attacks."""
    await init_db()
    
    # Generate correlations
    for i in range(corr_count):
        flow_count = random.randint(2, 5)
        flows = []
        for _ in range(flow_count):
            src = random.choice(IPS)
            dst = random.choice(IPS)
            while dst == src:
                dst = random.choice(IPS)
            flows.append(f"{src}:{random.randint(1024, 65535)}->{dst}:{random.choice([80, 443, 8080, 22])}")
        
        corr = {
            "correlated_flows": ",".join(flows),
            "correlation_type": random.choice(CORRELATION_TYPES),
            "temporal_overlap": random.uniform(0.3, 0.95),
            "correlation_score": random.uniform(0.5, 0.99),
            "timestamp": time.time() - random.randint(0, 3600),
            "flow_count": flow_count
        }
        
        await insert_correlation(corr)
        print(f"Inserted correlation {i+1}/{corr_count}: {corr['correlation_type']} ({corr['correlation_score']:.2f})")
    
    # Generate coordinated attacks
    for i in range(attack_count):
        attack = {
            "source_ip": random.choice(IPS),
            "protocols": ",".join(random.sample(PROTOCOLS, random.randint(2, 3))),
            "flow_count": random.randint(5, 20),
            "correlation_score": random.uniform(0.75, 0.99),
            "timestamp": time.time() - random.randint(0, 1800)
        }
        
        await insert_coordinated_attack(attack)
        print(f"Inserted coordinated attack {i+1}/{attack_count}: {attack['source_ip']} ({attack['correlation_score']:.2f})")
    
    print(f"\nSuccessfully populated {corr_count} correlations and {attack_count} coordinated attacks")

if __name__ == "__main__":
    asyncio.run(populate_correlation_data(30, 5))
