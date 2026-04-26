#pragma once
#include <vector>
#include <string>
#include <unordered_map>

namespace covert {

struct ProtocolFeatures {
    double mean_iat;
    double std_iat;
    double mean_size;
    double entropy;
    double burst_ratio;
};

class ProtocolAgnostic {
public:
    ProtocolAgnostic();
    
    ProtocolFeatures extract_universal_features(const std::vector<uint8_t>& packet_data,
                                                 const std::vector<double>& timestamps);
    
    double calculate_protocol_similarity(const ProtocolFeatures& f1, 
                                         const ProtocolFeatures& f2);
    
    bool detect_covert_channel_agnostic(const ProtocolFeatures& features, 
                                        double threshold = 0.7);
    
private:
    std::unordered_map<std::string, ProtocolFeatures> baseline_profiles_;
    
    double calculate_iat_entropy(const std::vector<double>& timestamps);
    double calculate_size_entropy(const std::vector<uint8_t>& packet_data);
};

} // namespace covert
