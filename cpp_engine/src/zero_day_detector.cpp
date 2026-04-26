#include "zero_day_detector.hpp"
#include <cmath>
#include <algorithm>
#include <numeric>
#include <random>

namespace covert {

ZeroDayDetector::ZeroDayDetector(int n_trees, double contamination)
    : n_trees_(n_trees), contamination_(contamination) {}

void ZeroDayDetector::fit(const std::vector<FlowFeatures>& normal_traffic) {
    training_data_ = normal_traffic;
}

std::vector<double> ZeroDayDetector::normalize_features(const FlowFeatures& flow) {
    return {
        flow.mean_iat,
        flow.std_iat,
        flow.mean_packet_size,
        flow.std_packet_size,
        flow.duration,
        flow.packets_per_second,
        flow.bytes_per_second,
        flow.entropy
    };
}

double ZeroDayDetector::calculate_isolation_score(const FlowFeatures& flow) {
    if (training_data_.empty()) return 0.5;
    
    auto features = normalize_features(flow);
    double avg_path_length = 0.0;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    
    for (int tree = 0; tree < n_trees_; ++tree) {
        int path_length = 0;
        int max_depth = static_cast<int>(std::log2(training_data_.size()));
        
        std::vector<FlowFeatures> subset = training_data_;
        
        while (subset.size() > 1 && path_length < max_depth) {
            std::uniform_int_distribution<> feature_dist(0, 7);
            int split_feature = feature_dist(gen);
            
            auto subset_features = normalize_features(subset[0]);
            double min_val = subset_features[split_feature];
            double max_val = subset_features[split_feature];
            
            for (const auto& s : subset) {
                auto sf = normalize_features(s);
                min_val = std::min(min_val, sf[split_feature]);
                max_val = std::max(max_val, sf[split_feature]);
            }
            
            if (max_val == min_val) break;
            
            std::uniform_real_distribution<> split_dist(min_val, max_val);
            double split_value = split_dist(gen);
            
            if (features[split_feature] < split_value) {
                subset.erase(std::remove_if(subset.begin(), subset.end(),
                    [&](const FlowFeatures& f) {
                        return normalize_features(f)[split_feature] >= split_value;
                    }), subset.end());
            } else {
                subset.erase(std::remove_if(subset.begin(), subset.end(),
                    [&](const FlowFeatures& f) {
                        return normalize_features(f)[split_feature] < split_value;
                    }), subset.end());
            }
            
            path_length++;
        }
        
        avg_path_length += path_length;
    }
    
    avg_path_length /= n_trees_;
    
    double c = 2.0 * (std::log(training_data_.size() - 1) + 0.5772156649) - 
               (2.0 * (training_data_.size() - 1) / training_data_.size());
    
    return std::pow(2.0, -avg_path_length / c);
}

double ZeroDayDetector::calculate_reconstruction_error(const FlowFeatures& flow) {
    if (training_data_.empty()) return 0.5;
    
    auto features = normalize_features(flow);
    
    std::vector<double> means(8, 0.0);
    for (const auto& train_flow : training_data_) {
        auto train_features = normalize_features(train_flow);
        for (size_t i = 0; i < 8; ++i) {
            means[i] += train_features[i];
        }
    }
    
    for (auto& mean : means) {
        mean /= training_data_.size();
    }
    
    double error = 0.0;
    for (size_t i = 0; i < 8; ++i) {
        error += std::pow(features[i] - means[i], 2);
    }
    
    return std::sqrt(error / 8.0);
}

AnomalyScore ZeroDayDetector::detect_anomaly(const FlowFeatures& flow) {
    AnomalyScore score;
    
    score.isolation_score = calculate_isolation_score(flow);
    score.autoencoder_score = calculate_reconstruction_error(flow);
    
    score.combined_score = (score.isolation_score + 
                           std::min(score.autoencoder_score, 1.0)) / 2.0;
    
    score.is_novel_pattern = score.combined_score > (1.0 - contamination_);
    
    return score;
}

bool ZeroDayDetector::is_novel_covert_channel(const FlowFeatures& flow, double threshold) {
    auto score = detect_anomaly(flow);
    return score.combined_score > threshold;
}

} // namespace covert
