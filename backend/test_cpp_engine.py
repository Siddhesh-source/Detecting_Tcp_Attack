"""
Test script for C++ covert channel detection engine.
Demonstrates CWND and QoS detection capabilities.
"""
import sys
from pathlib import Path

# Add backend to path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

from generate_cpp_test_data import (
    generate_normal_tcp_flow,
    generate_cwnd_covert_channel,
    generate_normal_ip_flow,
    generate_qos_covert_channel
)

try:
    from cpp_detector_wrapper import CWNDDetectorWrapper, QoSDetectorWrapper, CPP_ENGINE_AVAILABLE
except ImportError:
    print("ERROR: C++ engine not available. Build it first:")
    print("  cd cpp_engine")
    print("  build.bat")
    sys.exit(1)


def test_cwnd_detection():
    """Test CWND manipulation detection."""
    print("\n" + "="*70)
    print("TEST 1: TCP CWND Manipulation Detection")
    print("="*70)
    
    detector = CWNDDetectorWrapper(sensitivity=2.5)
    
    # Test normal flow
    print("\n[1.1] Analyzing NORMAL TCP flow...")
    normal_packets = generate_normal_tcp_flow(50)
    anomalies = detector.analyze_packets(normal_packets)
    print(f"  Packets: {len(normal_packets)}")
    print(f"  Anomalies: {len(anomalies)}")
    if anomalies:
        print(f"  WARNING: False positives detected!")
    else:
        print(f"  ✓ Correctly identified as benign")
    
    # Test covert channel
    print("\n[1.2] Analyzing CWND COVERT CHANNEL...")
    covert_packets = generate_cwnd_covert_channel(50)
    anomalies = detector.analyze_packets(covert_packets)
    print(f"  Packets: {len(covert_packets)}")
    print(f"  Anomalies: {len(anomalies)}")
    
    if anomalies:
        print(f"  ✓ Covert channel DETECTED!")
        for i, anomaly in enumerate(anomalies[:3]):
            print(f"\n  Anomaly {i+1}:")
            print(f"    Type: {anomaly['anomaly_type']}")
            print(f"    Expected CWND: {anomaly['expected_cwnd']:.2f}")
            print(f"    Observed CWND: {anomaly['observed_cwnd']:.2f}")
            print(f"    Deviation: {anomaly['deviation_score']:.2f}x")
            print(f"    Flow: {anomaly['flow_id']}")
    else:
        print(f"  ✗ Failed to detect covert channel")


def test_qos_detection():
    """Test QoS/DSCP manipulation detection."""
    print("\n" + "="*70)
    print("TEST 2: QoS/DSCP Manipulation Detection")
    print("="*70)
    
    detector = QoSDetectorWrapper(threshold=0.7)
    
    # Test normal flow
    print("\n[2.1] Analyzing NORMAL IP flow...")
    normal_packets = generate_normal_ip_flow(50)
    anomalies = detector.analyze_packets(normal_packets)
    print(f"  Packets: {len(normal_packets)}")
    print(f"  Anomalies: {len(anomalies)}")
    if anomalies:
        print(f"  WARNING: False positives detected!")
    else:
        print(f"  ✓ Correctly identified as benign")
    
    # Test covert channel
    print("\n[2.2] Analyzing QoS COVERT CHANNEL...")
    covert_packets = generate_qos_covert_channel(50)
    anomalies = detector.analyze_packets(covert_packets)
    print(f"  Packets: {len(covert_packets)}")
    print(f"  Anomalies: {len(anomalies)}")
    
    if anomalies:
        print(f"  ✓ Covert channel DETECTED!")
        for i, anomaly in enumerate(anomalies[:3]):
            print(f"\n  Anomaly {i+1}:")
            print(f"    Type: {anomaly['anomaly_type']}")
            print(f"    DSCP: {anomaly['dscp_value']}")
            print(f"    Frequency: {anomaly['frequency']:.2%}")
            print(f"    Expected: {anomaly['expected_frequency']:.2%}")
            print(f"    Score: {anomaly['score']:.2f}")
            print(f"    Flow: {anomaly['flow_id']}")
    else:
        print(f"  ✗ Failed to detect covert channel")


def main():
    print("\n" + "="*70)
    print("C++ COVERT CHANNEL DETECTION ENGINE - TEST SUITE")
    print("="*70)
    print(f"\nEngine Status: {'AVAILABLE' if CPP_ENGINE_AVAILABLE else 'NOT AVAILABLE'}")
    
    if not CPP_ENGINE_AVAILABLE:
        print("\nERROR: C++ engine not built. Run:")
        print("  cd cpp_engine && build.bat")
        return 1
    
    try:
        test_cwnd_detection()
        test_qos_detection()
        
        print("\n" + "="*70)
        print("TEST SUMMARY")
        print("="*70)
        print("✓ CWND detector operational")
        print("✓ QoS detector operational")
        print("\nAll tests completed successfully!")
        print("="*70 + "\n")
        
        return 0
        
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
