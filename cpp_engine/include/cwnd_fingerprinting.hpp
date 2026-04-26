#pragma once
#include <vector>
#include <string>
#include <unordered_map>

namespace covert {

enum class CongestionAlgorithm {
    UNKNOWN,
    RENO,
    CUBIC,
    BBR,
    VEGAS
};

struct AlgorithmFingerprint {
    CongestionAlgorithm algorithm;
    double confidence;
    std::vector<double> signature_features;
};

class CWNDFingerprinting {
public:
    CWNDFingerprinting();
    
    AlgorithmFingerprint identify_algorithm(const std::vector<double>& cwnd_sequence);
    
    double estimate_expected_cwnd(CongestionAlgorithm algo, int rtt_ms, int mss, 
                                   double time_since_loss, int packets_acked);
    
    bool detect_algorithm_switching(const std::vector<AlgorithmFingerprint>& history);
    
private:
    double calculate_growth_rate(const std::vector<double>& cwnd_sequence);
    double calculate_loss_response_ratio(const std::vector<double>& cwnd_sequence);
    bool has_cubic_pattern(const std::vector<double>& cwnd_sequence);
    bool has_bbr_pattern(const std::vector<double>& cwnd_sequence);
    
    std::unordered_map<CongestionAlgorithm, std::vector<double>> algorithm_signatures_;
};

} // namespace covert
