#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <unordered_map>

namespace covert {

struct IPPacket {
    uint8_t dscp;
    uint8_t ecn;
    uint16_t total_length;
    double timestamp;
    std::string src_ip;
    std::string dst_ip;
    uint16_t ip_id;
};

struct QoSAnomaly {
    double timestamp;
    uint8_t dscp_value;
    double frequency;
    double expected_frequency;
    std::string anomaly_type;
    double score;
    std::string flow_id;
};

class QoSDetector {
public:
    explicit QoSDetector(double threshold = 0.7);
    
    std::vector<QoSAnomaly> analyze_dscp_patterns(const std::vector<IPPacket>& packets);
    bool detect_dscp_hopping(const std::vector<uint8_t>& dscp_sequence);
    bool detect_priority_encoding(const std::vector<uint8_t>& dscp_sequence);
    bool detect_ecn_abuse(const std::vector<IPPacket>& packets);
    double calculate_dscp_entropy(const std::vector<uint8_t>& dscp_values);
    std::unordered_map<uint8_t, double> build_dscp_profile(const std::vector<IPPacket>& packets);
    
private:
    double threshold_;
    double chi_square_test(const std::vector<double>& observed, const std::vector<double>& expected);
};

} // namespace covert
