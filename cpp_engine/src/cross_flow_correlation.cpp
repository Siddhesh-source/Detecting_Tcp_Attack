#include "cross_flow_correlation.hpp"
#include <algorithm>
#include <cmath>
#include <set>

namespace covert {

CrossFlowCorrelation::CrossFlowCorrelation(double time_window) 
    : time_window_(time_window) {}

bool CrossFlowCorrelation::same_source(const FlowMetadata& flow1, const FlowMetadata& flow2) {
    return flow1.src_ip == flow2.src_ip;
}

bool CrossFlowCorrelation::temporal_overlap(const FlowMetadata& flow1, const FlowMetadata& flow2) {
    double overlap_start = std::max(flow1.start_time, flow2.start_time);
    double overlap_end = std::min(flow1.end_time, flow2.end_time);
    return overlap_end > overlap_start;
}

double CrossFlowCorrelation::calculate_temporal_correlation(const FlowMetadata& flow1, 
                                                            const FlowMetadata& flow2) {
    if (!temporal_overlap(flow1, flow2)) {
        double gap = std::min(std::abs(flow1.start_time - flow2.end_time),
                             std::abs(flow2.start_time - flow1.end_time));
        if (gap > time_window_) return 0.0;
        return 1.0 - (gap / time_window_);
    }
    
    double overlap_start = std::max(flow1.start_time, flow2.start_time);
    double overlap_end = std::min(flow1.end_time, flow2.end_time);
    double overlap_duration = overlap_end - overlap_start;
    
    double total_duration = std::max(flow1.end_time, flow2.end_time) - 
                           std::min(flow1.start_time, flow2.start_time);
    
    return overlap_duration / total_duration;
}

double CrossFlowCorrelation::calculate_protocol_diversity(const std::vector<FlowMetadata>& flows) {
    std::set<std::string> protocols;
    for (const auto& flow : flows) {
        protocols.insert(flow.protocol);
    }
    return static_cast<double>(protocols.size());
}

std::vector<CorrelationResult> CrossFlowCorrelation::find_correlated_flows(
    const std::vector<FlowMetadata>& flows) {
    
    std::vector<CorrelationResult> results;
    std::unordered_map<std::string, std::vector<FlowMetadata>> flows_by_source;
    
    for (const auto& flow : flows) {
        flows_by_source[flow.src_ip].push_back(flow);
    }
    
    for (const auto& [src_ip, src_flows] : flows_by_source) {
        if (src_flows.size() < 2) continue;
        
        for (size_t i = 0; i < src_flows.size(); ++i) {
            for (size_t j = i + 1; j < src_flows.size(); ++j) {
                double temporal_corr = calculate_temporal_correlation(src_flows[i], src_flows[j]);
                
                if (temporal_corr > 0.5) {
                    CorrelationResult result;
                    result.correlated_flows = {src_flows[i].flow_id, src_flows[j].flow_id};
                    result.temporal_overlap = temporal_corr;
                    result.correlation_score = (src_flows[i].suspicion_score + 
                                               src_flows[j].suspicion_score) / 2.0 * temporal_corr;
                    
                    if (src_flows[i].protocol != src_flows[j].protocol) {
                        result.correlation_type = "multi_protocol";
                        result.correlation_score *= 1.5;
                    } else {
                        result.correlation_type = "same_protocol";
                    }
                    
                    results.push_back(result);
                }
            }
        }
    }
    
    std::sort(results.begin(), results.end(), 
              [](const CorrelationResult& a, const CorrelationResult& b) {
                  return a.correlation_score > b.correlation_score;
              });
    
    return results;
}

bool CrossFlowCorrelation::detect_coordinated_attack(const std::vector<FlowMetadata>& flows) {
    auto correlations = find_correlated_flows(flows);
    
    if (correlations.empty()) return false;
    
    int high_correlation_count = 0;
    for (const auto& corr : correlations) {
        if (corr.correlation_score > 50.0 && corr.correlation_type == "multi_protocol") {
            high_correlation_count++;
        }
    }
    
    return high_correlation_count >= 2;
}

} // namespace covert
