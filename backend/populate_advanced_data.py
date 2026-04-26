"""
Populate Zero-Day, Adversarial, and Protocol-Agnostic data for testing.
"""
import asyncio
import random
import time
from database import (
    init_db, 
    insert_zeroday_detection, 
    insert_adversarial_metric,
    insert_sanitization_log,
    insert_protocol_feature
)

IPS = ["192.168.1.10", "192.168.1.20", "10.0.0.5", "172.16.0.100", "192.168.1.50"]
PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS"]
ATTACK_TYPES = ["FGSM", "PGD", "CW", "DeepFool", "boundary_attack"]
SANITIZATION_TYPES = ["clipping", "normalization", "feature_squeezing", "adversarial_training"]

async def populate_zeroday_data(count=40):
    """Generate zero-day detection data."""
    for i in range(count):
        src = random.choice(IPS)
        dst = random.choice(IPS)
        while dst == src:
            dst = random.choice(IPS)
        
        isolation = random.uniform(0.3, 0.95)
        autoencoder = random.uniform(0.2, 1.5)
        combined = (isolation + min(autoencoder, 1.0)) / 2
        is_novel = 1 if combined > 0.7 else 0
        
        detection = {
            "flow_id": f"{src}:{random.randint(1024, 65535)}->{dst}:{random.choice([80, 443, 8080])}",
            "isolation_score": isolation,
            "autoencoder_score": autoencoder,
            "combined_score": combined,
            "is_novel_pattern": is_novel,
            "timestamp": time.time() - random.randint(0, 3600)
        }
        
        await insert_zeroday_detection(detection)
        print(f"Zero-Day {i+1}/{count}: combined={combined:.3f} novel={bool(is_novel)}")

async def populate_adversarial_data(count=50):
    """Generate adversarial robustness data."""
    for i in range(count):
        src = random.choice(IPS)
        dst = random.choice(IPS)
        while dst == src:
            dst = random.choice(IPS)
        
        robustness = random.uniform(0.5, 0.95)
        perturbation = random.uniform(0.01, 0.3)
        is_attack = 1 if perturbation > 0.15 and robustness < 0.7 else 0
        
        metric = {
            "flow_id": f"{src}:{random.randint(1024, 65535)}->{dst}:{random.choice([80, 443, 22])}",
            "robustness_score": robustness,
            "perturbation_magnitude": perturbation,
            "attack_type": random.choice(ATTACK_TYPES) if is_attack else "none",
            "confidence": random.uniform(0.7, 0.99) if is_attack else 0.0,
            "is_attack": is_attack,
            "timestamp": time.time() - random.randint(0, 3600)
        }
        
        await insert_adversarial_metric(metric)
        print(f"Adversarial {i+1}/{count}: robustness={robustness:.3f} attack={bool(is_attack)}")
        
        # Add sanitization logs for some flows
        if random.random() > 0.7:
            log = {
                "flow_id": metric["flow_id"],
                "features_modified": random.randint(1, 8),
                "sanitization_type": random.choice(SANITIZATION_TYPES),
                "timestamp": metric["timestamp"] + random.uniform(0.1, 1.0)
            }
            await insert_sanitization_log(log)

async def populate_protocol_agnostic_data(count=60):
    """Generate protocol-agnostic feature data."""
    for i in range(count):
        src = random.choice(IPS)
        dst = random.choice(IPS)
        while dst == src:
            dst = random.choice(IPS)
        
        protocol = random.choice(PROTOCOLS)
        mean_iat = random.uniform(0.001, 0.1)
        mean_size = random.randint(40, 1500)
        entropy = random.uniform(3.0, 8.0)
        burst_ratio = random.uniform(0.1, 0.9)
        
        # Covert channels typically have low IAT variance, specific sizes, high entropy
        is_covert = 1 if (mean_iat < 0.01 and entropy > 6.5 and burst_ratio > 0.7) else 0
        
        feature = {
            "flow_id": f"{src}:{random.randint(1024, 65535)}->{dst}:{random.choice([80, 443, 53, 8080])}",
            "protocol": protocol,
            "mean_iat": mean_iat,
            "mean_size": mean_size,
            "entropy": entropy,
            "burst_ratio": burst_ratio,
            "is_covert": is_covert,
            "timestamp": time.time() - random.randint(0, 3600)
        }
        
        await insert_protocol_feature(feature)
        print(f"Protocol {i+1}/{count}: {protocol} entropy={entropy:.2f} covert={bool(is_covert)}")

async def main():
    await init_db()
    print("Populating Zero-Day detections...")
    await populate_zeroday_data(40)
    print("\nPopulating Adversarial metrics...")
    await populate_adversarial_data(50)
    print("\nPopulating Protocol-Agnostic features...")
    await populate_protocol_agnostic_data(60)
    print("\nAll data populated successfully!")

if __name__ == "__main__":
    asyncio.run(main())
