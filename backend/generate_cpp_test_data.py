"""
Generate synthetic test data for CWND and QoS covert channel detection.
"""
import random
import time
from typing import List, Dict


def generate_normal_tcp_flow(num_packets=100, base_ip="192.168.1") -> List[Dict]:
    """Generate normal TCP flow with realistic CWND behavior."""
    packets = []
    seq_num = random.randint(1000, 10000)
    ack_num = random.randint(1000, 10000)
    cwnd = 10  # Initial congestion window
    timestamp = time.time()
    
    for i in range(num_packets):
        packets.append({
            'seq_num': seq_num,
            'ack_num': ack_num,
            'window_size': cwnd * 1460,  # MSS = 1460
            'timestamp': timestamp + i * 0.05,  # 50ms intervals
            'payload_size': 1460,
            'syn': i == 0,
            'ack': i > 0,
            'fin': i == num_packets - 1,
            'rst': False,
            'src_ip': f"{base_ip}.{random.randint(10, 50)}",
            'dst_ip': f"{base_ip}.{random.randint(100, 200)}",
            'src_port': random.randint(40000, 60000),
            'dst_port': 80
        })
        
        seq_num += 1460
        ack_num += 1460
        
        # Simulate TCP Reno congestion control
        if i % 20 == 0:  # Simulate packet loss
            cwnd = max(1, cwnd // 2)
        else:
            cwnd = min(cwnd + 1, 100)
    
    return packets


def generate_cwnd_covert_channel(num_packets=100, base_ip="192.168.1") -> List[Dict]:
    """Generate TCP flow with CWND manipulation for covert channel."""
    packets = []
    seq_num = random.randint(1000, 10000)
    ack_num = random.randint(1000, 10000)
    timestamp = time.time()
    
    # Encode message in CWND oscillations
    message = "SECRET"
    message_bits = ''.join(format(ord(c), '08b') for c in message)
    
    for i in range(num_packets):
        # Use CWND to encode bits: high window = 1, low window = 0
        bit_index = i % len(message_bits)
        cwnd = 50 if message_bits[bit_index] == '1' else 10
        
        packets.append({
            'seq_num': seq_num,
            'ack_num': ack_num,
            'window_size': cwnd * 1460,
            'timestamp': timestamp + i * 0.05,
            'payload_size': 1460,
            'syn': i == 0,
            'ack': i > 0,
            'fin': i == num_packets - 1,
            'rst': False,
            'src_ip': f"{base_ip}.{random.randint(10, 50)}",
            'dst_ip': f"{base_ip}.{random.randint(100, 200)}",
            'src_port': random.randint(40000, 60000),
            'dst_port': 443
        })
        
        seq_num += 1460
        ack_num += 1460
    
    return packets


def generate_normal_ip_flow(num_packets=100, base_ip="10.0.0") -> List[Dict]:
    """Generate normal IP flow with standard DSCP values."""
    packets = []
    timestamp = time.time()
    
    for i in range(num_packets):
        packets.append({
            'dscp': 0,  # Best Effort
            'ecn': 0,
            'total_length': random.randint(500, 1500),
            'timestamp': timestamp + i * 0.01,
            'src_ip': f"{base_ip}.{random.randint(10, 50)}",
            'dst_ip': f"{base_ip}.{random.randint(100, 200)}",
            'ip_id': random.randint(1000, 65000)
        })
    
    return packets


def generate_qos_covert_channel(num_packets=100, base_ip="10.0.0") -> List[Dict]:
    """Generate IP flow with DSCP manipulation for covert channel."""
    packets = []
    timestamp = time.time()
    
    # Encode message in DSCP field
    message = "HIDDEN"
    message_bits = ''.join(format(ord(c), '08b') for c in message)
    
    for i in range(num_packets):
        # Use DSCP to encode bits (6-bit field)
        bit_index = i % len(message_bits)
        dscp = 46 if message_bits[bit_index] == '1' else 10  # EF vs AF11
        
        packets.append({
            'dscp': dscp,
            'ecn': random.randint(0, 1),  # Also manipulate ECN
            'total_length': random.randint(500, 1500),
            'timestamp': timestamp + i * 0.01,
            'src_ip': f"{base_ip}.{random.randint(10, 50)}",
            'dst_ip': f"{base_ip}.{random.randint(100, 200)}",
            'ip_id': random.randint(1000, 65000)
        })
    
    return packets


if __name__ == "__main__":
    print("Generating test data...")
    
    print("\n1. Normal TCP flow:")
    normal_tcp = generate_normal_tcp_flow(50)
    print(f"   Generated {len(normal_tcp)} packets")
    
    print("\n2. CWND covert channel:")
    cwnd_covert = generate_cwnd_covert_channel(50)
    print(f"   Generated {len(cwnd_covert)} packets")
    
    print("\n3. Normal IP flow:")
    normal_ip = generate_normal_ip_flow(50)
    print(f"   Generated {len(normal_ip)} packets")
    
    print("\n4. QoS covert channel:")
    qos_covert = generate_qos_covert_channel(50)
    print(f"   Generated {len(qos_covert)} packets")
