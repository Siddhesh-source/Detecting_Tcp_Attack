#include "cwnd_detector.hpp"
#include <cmath>
#include <algorithm>
#include <numeric>
#include <unordered_map>

namespace covert {

CWNDDetector::CWNDDetector(double sensitivity) : sensitivity_(sensitivity) {}

std::vector<double> CWNDDetector::extract_cwnd_sequence(const std::vector<TCPPacket>& packets) {
    std::vector<double> cwnd_estimates;
    std::unordered_map<std::string, uint32_t> last_ack;
    
    for (const auto& pkt : packets) {
        if (!pkt.ack) continue;
        
        std::string flow_key = pkt.src_ip + ":" + std::to_string(pkt.src_port);
        auto it = last_ack.find(flow_key);
        
        if (it != last_ack.end()) {
            uint32_t acked_bytes = pkt.ack_num - it->second;
            double estimated_cwnd = static_cast<double>(pkt.window_size);
            cwnd_estimates.push_back(estimated_cwnd);
        }
        last_ack[flow_key] = pkt.ack_num;
    }
    
    return cwnd_estimates;
}

double CWNDDetector::estimate_cwnd_reno(int rtt_ms, int mss, int packets_acked) {
    // TCP Reno: CWND grows by 1 MSS per RTT in congestion avoidance
    return static_cast<double>(mss * packets_acked);
}

double CWNDDetector::estimate_cwnd_cubic(int rtt_ms, int mss, double time_since_loss) {
    // CUBIC: W_cubic(t) = C(t - K)^3 + W_max
    const double C = 0.4;
    const double beta = 0.7;
    double W_max = 100.0 * mss;
    double K = std::cbrt(W_max * (1 - beta) / C);
    double t = time_since_loss;
    
    return C * std::pow(t - K, 3) + W_max;
}

double CWNDDetector::calculate_entropy(const std::vector<double>& values) {
    if (values.empty()) return 0.0;
    
    std::unordered_map<int, int> freq;
    for (double v : values) {
        freq[static_cast<int>(v)]++;
    }
    
    double entropy = 0.0;
    double total = static_cast<double>(values.size());
    
    for (const auto& [val, count] : freq) {
        double p = count / total;
        if (p > 0) {
            entropy -= p * std::log2(p);
        }
    }
    
    return entropy;
}

double CWNDDetector::calculate_autocorrelation(const std::vector<double>& values, int lag) {
    if (values.size() <= static_cast<size_t>(lag)) return 0.0;
    
    double mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    
    double numerator = 0.0;
    double denominator = 0.0;
    
    for (size_t i = 0; i < values.size() - lag; ++i) {
        numerator += (values[i] - mean) * (values[i + lag] - mean);
    }
    
    for (size_t i = 0; i < values.size(); ++i) {
        denominator += (values[i] - mean) * (values[i] - mean);
    }
    
    return denominator > 0 ? numerator / denominator : 0.0;
}

bool CWNDDetector::detect_artificial_inflation(const std::vector<double>& cwnd_history) {
    if (cwnd_history.size() < 10) return false;
    
    // Check for sustained growth without expected sawtooth pattern
    int consecutive_increases = 0;
    for (size_t i = 1; i < cwnd_history.size(); ++i) {
        if (cwnd_history[i] > cwnd_history[i-1]) {
            consecutive_increases++;
        } else {
            consecutive_increases = 0;
        }
        
        if (consecutive_increases > 20) return true;
    }
    
    return false;
}

bool CWNDDetector::detect_sawtooth_encoding(const std::vector<double>& cwnd_history) {
    if (cwnd_history.size() < 20) return false;
    
    // Detect abnormal periodicity in CWND oscillations
    double autocorr_lag1 = calculate_autocorrelation(cwnd_history, 1);
    double autocorr_lag5 = calculate_autocorrelation(cwnd_history, 5);
    
    // Covert channels show high periodicity
    return (autocorr_lag1 > 0.8 || autocorr_lag5 > 0.7);
}

bool CWNDDetector::detect_window_oscillation(const std::vector<double>& cwnd_history) {
    if (cwnd_history.size() < 10) return false;
    
    // Calculate variance and check for abnormal oscillation patterns
    double mean = std::accumulate(cwnd_history.begin(), cwnd_history.end(), 0.0) / cwnd_history.size();
    double variance = 0.0;
    
    for (double val : cwnd_history) {
        variance += (val - mean) * (val - mean);
    }
    variance /= cwnd_history.size();
    
    double std_dev = std::sqrt(variance);
    double cv = std_dev / mean; // Coefficient of variation
    
    // High CV indicates abnormal oscillation
    return cv > 0.5;
}

std::vector<CWNDAnomaly> CWNDDetector::analyze_flow(const std::vector<TCPPacket>& packets) {
    std::vector<CWNDAnomaly> anomalies;
    
    if (packets.empty()) return anomalies;
    
    std::vector<double> cwnd_sequence = extract_cwnd_sequence(packets);
    
    if (cwnd_sequence.size() < 10) return anomalies;
    
    // Detect various manipulation patterns
    bool inflation = detect_artificial_inflation(cwnd_sequence);
    bool sawtooth = detect_sawtooth_encoding(cwnd_sequence);
    bool oscillation = detect_window_oscillation(cwnd_sequence);
    
    if (inflation || sawtooth || oscillation) {
        for (size_t i = 0; i < packets.size() && i < cwnd_sequence.size(); ++i) {
            const auto& pkt = packets[i];
            double observed = cwnd_sequence[i];
            double expected = estimate_cwnd_reno(50, 1460, static_cast<int>(i));
            double deviation = std::abs(observed - expected) / expected;
            
            if (deviation > sensitivity_) {
                CWNDAnomaly anomaly;
                anomaly.timestamp = pkt.timestamp;
                anomaly.expected_cwnd = expected;
                anomaly.observed_cwnd = observed;
                anomaly.deviation_score = deviation;
                anomaly.flow_id = pkt.src_ip + ":" + std::to_string(pkt.src_port) + 
                                  "->" + pkt.dst_ip + ":" + std::to_string(pkt.dst_port);
                
                if (inflation) anomaly.anomaly_type = "artificial_inflation";
                else if (sawtooth) anomaly.anomaly_type = "sawtooth_encoding";
                else if (oscillation) anomaly.anomaly_type = "window_oscillation";
                
                anomalies.push_back(anomaly);
            }
        }
    }
    
    return anomalies;
}

} // namespace covert
