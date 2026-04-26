#pragma once
#include <vector>
#include <string>
#include <unordered_map>

namespace covert {

struct FlowMetadata {
    std::string flow_id;
    std::string src_ip;
    std::string dst_ip;
    double start_time;
    double end_time;
    std::string protocol;
    double suspicion_score;
};

struct CorrelationResult {
    std::vector<std::string> correlated_flows;
    double correlation_score;
    std::string correlation_type;
    double temporal_overlap;
};

class CrossFlowCorrelation {
public:
    CrossFlowCorrelation(double time_window = 60.0);
    
    std::vector<CorrelationResult> find_correlated_flows(
        const std::vector<FlowMetadata>& flows);
    
    bool detect_coordinated_attack(const std::vector<FlowMetadata>& flows);
    
    double calculate_temporal_correlation(const FlowMetadata& flow1, 
                                          const FlowMetadata& flow2);
    
private:
    double time_window_;
    
    bool same_source(const FlowMetadata& flow1, const FlowMetadata& flow2);
    bool temporal_overlap(const FlowMetadata& flow1, const FlowMetadata& flow2);
    double calculate_protocol_diversity(const std::vector<FlowMetadata>& flows);
};

} // namespace covert
