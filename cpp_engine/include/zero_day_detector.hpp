#pragma once
#include <vector>
#include <string>

namespace covert {

struct FlowFeatures {
    double mean_iat;
    double std_iat;
    double mean_packet_size;
    double std_packet_size;
    double duration;
    double packets_per_second;
    double bytes_per_second;
    double entropy;
};

struct AnomalyScore {
    double isolation_score;
    double autoencoder_score;
    double combined_score;
    bool is_novel_pattern;
};

class ZeroDayDetector {
public:
    ZeroDayDetector(int n_trees = 100, double contamination = 0.1);
    
    void fit(const std::vector<FlowFeatures>& normal_traffic);
    
    AnomalyScore detect_anomaly(const FlowFeatures& flow);
    
    bool is_novel_covert_channel(const FlowFeatures& flow, double threshold = 0.7);
    
private:
    int n_trees_;
    double contamination_;
    std::vector<FlowFeatures> training_data_;
    
    double calculate_isolation_score(const FlowFeatures& flow);
    double calculate_reconstruction_error(const FlowFeatures& flow);
    std::vector<double> normalize_features(const FlowFeatures& flow);
};

} // namespace covert
