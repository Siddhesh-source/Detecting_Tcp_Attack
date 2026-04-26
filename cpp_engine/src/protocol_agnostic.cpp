#include "protocol_agnostic.hpp"
#include <cmath>
#include <algorithm>
#include <unordered_map>

namespace covert {

ProtocolAgnostic::ProtocolAgnostic() {
    baseline_profiles_["normal"] = {0.05, 0.02, 500.0, 5.0, 0.3};
}

double ProtocolAgnostic::calculate_iat_entropy(const std::vector<double>& timestamps) {
    if (timestamps.size() < 2) return 0.0;
    
    std::vector<double> iats;
    for (size_t i = 1; i < timestamps.size(); ++i) {
        iats.push_back(timestamps[i] - timestamps[i-1]);
    }
    
    std::unordered_map<int, int> freq;
    for (double iat : iats) {
        int bucket = static_cast<int>(iat * 1000);
        freq[bucket]++;
    }
    
    double entropy = 0.0;
    double total = static_cast<double>(iats.size());
    
    for (const auto& [bucket, count] : freq) {
        double p = count / total;
        if (p > 0) {
            entropy -= p * std::log2(p);
        }
    }
    
    return entropy;
}

double ProtocolAgnostic::calculate_size_entropy(const std::vector<uint8_t>& packet_data) {
    if (packet_data.empty()) return 0.0;
    
    std::unordered_map<uint8_t, int> freq;
    for (uint8_t byte : packet_data) {
        freq[byte]++;
    }
    
    double entropy = 0.0;
    double total = static_cast<double>(packet_data.size());
    
    for (const auto& [byte, count] : freq) {
        double p = count / total;
        if (p > 0) {
            entropy -= p * std::log2(p);
        }
    }
    
    return entropy;
}

ProtocolFeatures ProtocolAgnostic::extract_universal_features(
    const std::vector<uint8_t>& packet_data,
    const std::vector<double>& timestamps) {
    
    ProtocolFeatures features;
    
    if (timestamps.size() >= 2) {
        std::vector<double> iats;
        for (size_t i = 1; i < timestamps.size(); ++i) {
            iats.push_back(timestamps[i] - timestamps[i-1]);
        }
        
        double sum = 0.0;
        for (double iat : iats) sum += iat;
        features.mean_iat = sum / iats.size();
        
        double var = 0.0;
        for (double iat : iats) {
            var += (iat - features.mean_iat) * (iat - features.mean_iat);
        }
        features.std_iat = std::sqrt(var / iats.size());
    }
    
    features.mean_size = packet_data.empty() ? 0.0 : 
                        static_cast<double>(packet_data.size());
    
    features.entropy = calculate_size_entropy(packet_data);
    
    int burst_count = 0;
    for (size_t i = 1; i < timestamps.size(); ++i) {
        if (timestamps[i] - timestamps[i-1] < 0.01) {
            burst_count++;
        }
    }
    features.burst_ratio = timestamps.empty() ? 0.0 : 
                          static_cast<double>(burst_count) / timestamps.size();
    
    return features;
}

double ProtocolAgnostic::calculate_protocol_similarity(const ProtocolFeatures& f1,
                                                       const ProtocolFeatures& f2) {
    double iat_diff = std::abs(f1.mean_iat - f2.mean_iat) / 
                     std::max(f1.mean_iat, f2.mean_iat);
    double size_diff = std::abs(f1.mean_size - f2.mean_size) / 
                      std::max(f1.mean_size, f2.mean_size);
    double entropy_diff = std::abs(f1.entropy - f2.entropy) / 
                         std::max(f1.entropy, f2.entropy);
    
    double total_diff = (iat_diff + size_diff + entropy_diff) / 3.0;
    
    return 1.0 - total_diff;
}

bool ProtocolAgnostic::detect_covert_channel_agnostic(const ProtocolFeatures& features,
                                                       double threshold) {
    const auto& baseline = baseline_profiles_["normal"];
    
    double similarity = calculate_protocol_similarity(features, baseline);
    
    bool low_iat_variance = features.std_iat < 0.01;
    bool high_burst_ratio = features.burst_ratio > 0.7;
    bool abnormal_entropy = features.entropy < 2.0 || features.entropy > 7.0;
    
    return (similarity < threshold) || low_iat_variance || 
           high_burst_ratio || abnormal_entropy;
}

} // namespace covert
