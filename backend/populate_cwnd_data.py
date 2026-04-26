"""
Populate CWND fingerprint data for testing.
Run this to add sample CWND fingerprints to the database.
"""
import asyncio
import random
import time
from database import init_db, insert_cwnd_fingerprint

ALGORITHMS = ["RENO", "CUBIC", "BBR", "VEGAS"]
IPS = ["192.168.1.10", "192.168.1.20", "10.0.0.5", "172.16.0.100"]

async def populate_cwnd_data(count=50):
    """Generate and insert sample CWND fingerprints."""
    await init_db()
    
    for i in range(count):
        src_ip = random.choice(IPS)
        dst_ip = random.choice(IPS)
        while dst_ip == src_ip:
            dst_ip = random.choice(IPS)
        
        algorithm = random.choice(ALGORITHMS)
        
        # Algorithm-specific characteristics
        if algorithm == "RENO":
            growth_rate = random.uniform(0.8, 1.2)
            loss_response = random.uniform(0.4, 0.6)
            confidence = random.uniform(0.7, 0.95)
        elif algorithm == "CUBIC":
            growth_rate = random.uniform(1.5, 2.5)
            loss_response = random.uniform(0.6, 0.8)
            confidence = random.uniform(0.75, 0.98)
        elif algorithm == "BBR":
            growth_rate = random.uniform(2.0, 3.5)
            loss_response = random.uniform(0.1, 0.3)
            confidence = random.uniform(0.8, 0.99)
        else:  # VEGAS
            growth_rate = random.uniform(0.5, 1.0)
            loss_response = random.uniform(0.3, 0.5)
            confidence = random.uniform(0.65, 0.9)
        
        fp = {
            "flow_id": f"{src_ip}:{random.randint(1024, 65535)}->{dst_ip}:{random.choice([80, 443, 8080, 22])}",
            "algorithm": algorithm,
            "confidence": confidence,
            "growth_rate": growth_rate,
            "loss_response": loss_response,
            "timestamp": time.time() - random.randint(0, 3600),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 8080, 22])
        }
        
        await insert_cwnd_fingerprint(fp)
        print(f"Inserted fingerprint {i+1}/{count}: {algorithm} ({confidence:.2f})")
    
    print(f"\n✓ Successfully populated {count} CWND fingerprints")

if __name__ == "__main__":
    asyncio.run(populate_cwnd_data(50))
