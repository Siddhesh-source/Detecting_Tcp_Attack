#include "qos_detector.hpp"
#include <cmath>
#include <algorithm>
#include <numeric>

namespace covert {

QoSDetector::QoSDetector(double threshold) : threshold_(threshold) {}

double QoSDetector::calculate_dscp_entropy(const std::vector<uint8_t>& dscp_values) {
    if (dscp_values.empty()) return 0.0;
    
    std::unordered_map<uint8_t, int> freq;
    for (uint8_t dscp : dscp_values) {
        freq[dscp]++;
    }
    
    double entropy = 0.0;
    double total = static_cast<double>(dscp_values.size());
    
    for (const auto& [val, count] : freq) {
        double p = count / total;
        if (p > 0) {
            entropy -= p * std::log2(p);
        }
    }
    
    return entropy;
}

std::unordered_map<uint8_t, double> QoSDetector::build_dscp_profile(const std::vector<IPPacket>& packets) {
    std::unordered_map<uint8_t, int> counts;
    
    for (const auto& pkt : packets) {
        counts[pkt.dscp]++;
    }
    
    std::unordered_map<uint8_t, double> profile;
    double total = static_cast<double>(packets.size());
    
    for (const auto& [dscp, count] : counts) {
        profile[dscp] = count / total;
    }
    
    return profile;
}

double QoSDetector::chi_square_test(const std::vector<double>& observed, const std::vector<double>& expected) {
    if (observed.size() != expected.size()) return 0.0;
    
    double chi_square = 0.0;
    
    for (size_t i = 0; i < observed.size(); ++i) {
        if (expected[i] > 0) {
            double diff = observed[i] - expected[i];
            chi_square += (diff * diff) / expected[i];
        }
    }
    
    return chi_square;
}

bool QoSDetector::detect_dscp_hopping(const std::vector<uint8_t>& dscp_sequence) {
    if (dscp_sequence.size() < 10) return false;
    
    // Count transitions between different DSCP values
    int transitions = 0;
    for (size_t i = 1; i < dscp_sequence.size(); ++i) {
        if (dscp_sequence[i] != dscp_sequence[i-1]) {
            transitions++;
        }
    }
    
    double transition_rate = static_cast<double>(transitions) / dscp_sequence.size();
    
    // High transition rate indicates DSCP hopping
    return transition_rate > 0.3;
}

bool QoSDetector::detect_priority_encoding(const std::vector<uint8_t>& dscp_sequence) {
    if (dscp_sequence.size() < 20) return false;
    
    // Check for patterns in DSCP values (e.g., alternating high/low priority)
    std::vector<uint8_t> unique_values;
    for (uint8_t val : dscp_sequence) {
        if (std::find(unique_values.begin(), unique_values.end(), val) == unique_values.end()) {
            unique_values.push_back(val);
        }
    }
    
    // Covert channels typically use 2-4 distinct DSCP values
    if (unique_values.size() < 2 || unique_values.size() > 4) return false;
    
    // Check for periodic patterns
    int pattern_matches = 0;
    for (size_t i = 2; i < dscp_sequence.size(); ++i) {
        if (dscp_sequence[i] == dscp_sequence[i-2]) {
            pattern_matches++;
        }
    }
    
    double periodicity = static_cast<double>(pattern_matches) / (dscp_sequence.size() - 2);
    
    return periodicity > 0.6;
}

bool QoSDetector::detect_ecn_abuse(const std::vector<IPPacket>& packets) {
    if (packets.size() < 10) return false;
    
    int ecn_set_count = 0;
    for (const auto& pkt : packets) {
        if (pkt.ecn != 0) {
            ecn_set_count++;
        }
    }
    
    double ecn_rate = static_cast<double>(ecn_set_count) / packets.size();
    
    // ECN should be rare in normal traffic
    return ecn_rate > 0.1;
}

std::vector<QoSAnomaly> QoSDetector::analyze_dscp_patterns(const std::vector<IPPacket>& packets) {
    std::vector<QoSAnomaly> anomalies;
    
    if (packets.empty()) return anomalies;
    
    // Extract DSCP sequence
    std::vector<uint8_t> dscp_sequence;
    for (const auto& pkt : packets) {
        dscp_sequence.push_back(pkt.dscp);
    }
    
    // Build frequency profile
    auto profile = build_dscp_profile(packets);
    
    // Calculate entropy
    double entropy = calculate_dscp_entropy(dscp_sequence);
    
    // Detect manipulation patterns
    bool hopping = detect_dscp_hopping(dscp_sequence);
    bool encoding = detect_priority_encoding(dscp_sequence);
    bool ecn_abuse = detect_ecn_abuse(packets);
    
    // Expected DSCP distribution (most traffic should be BE - Best Effort, DSCP=0)
    std::unordered_map<uint8_t, double> expected_profile = {{0, 0.95}, {46, 0.03}, {34, 0.02}};
    
    // Check each DSCP value for anomalies
    for (const auto& [dscp, freq] : profile) {
        double expected_freq = expected_profile.count(dscp) ? expected_profile[dscp] : 0.01;
        double deviation = std::abs(freq - expected_freq);
        
        if (deviation > threshold_ || hopping || encoding || ecn_abuse) {
            QoSAnomaly anomaly;
            anomaly.timestamp = packets[0].timestamp;
            anomaly.dscp_value = dscp;
            anomaly.frequency = freq;
            anomaly.expected_frequency = expected_freq;
            anomaly.score = deviation / expected_freq;
            anomaly.flow_id = packets[0].src_ip + "->" + packets[0].dst_ip;
            
            if (hopping) anomaly.anomaly_type = "dscp_hopping";
            else if (encoding) anomaly.anomaly_type = "priority_encoding";
            else if (ecn_abuse) anomaly.anomaly_type = "ecn_abuse";
            else anomaly.anomaly_type = "dscp_anomaly";
            
            anomalies.push_back(anomaly);
        }
    }
    
    return anomalies;
}

} // namespace covert
