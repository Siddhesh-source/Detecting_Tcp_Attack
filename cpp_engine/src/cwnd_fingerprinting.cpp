#include "cwnd_fingerprinting.hpp"
#include <cmath>
#include <algorithm>
#include <numeric>

namespace covert {

CWNDFingerprinting::CWNDFingerprinting() {
    algorithm_signatures_[CongestionAlgorithm::RENO] = {1.0, 0.5, 0.0};
    algorithm_signatures_[CongestionAlgorithm::CUBIC] = {0.4, 0.7, 1.0};
    algorithm_signatures_[CongestionAlgorithm::BBR] = {0.0, 0.0, 0.8};
    algorithm_signatures_[CongestionAlgorithm::VEGAS] = {0.8, 0.3, 0.2};
}

double CWNDFingerprinting::calculate_growth_rate(const std::vector<double>& cwnd_sequence) {
    if (cwnd_sequence.size() < 2) return 0.0;
    
    double total_growth = 0.0;
    int growth_count = 0;
    
    for (size_t i = 1; i < cwnd_sequence.size(); ++i) {
        if (cwnd_sequence[i] > cwnd_sequence[i-1]) {
            total_growth += (cwnd_sequence[i] - cwnd_sequence[i-1]) / cwnd_sequence[i-1];
            growth_count++;
        }
    }
    
    return growth_count > 0 ? total_growth / growth_count : 0.0;
}

double CWNDFingerprinting::calculate_loss_response_ratio(const std::vector<double>& cwnd_sequence) {
    if (cwnd_sequence.size() < 2) return 0.0;
    
    double total_decrease = 0.0;
    int decrease_count = 0;
    
    for (size_t i = 1; i < cwnd_sequence.size(); ++i) {
        if (cwnd_sequence[i] < cwnd_sequence[i-1]) {
            double ratio = cwnd_sequence[i] / cwnd_sequence[i-1];
            total_decrease += ratio;
            decrease_count++;
        }
    }
    
    return decrease_count > 0 ? total_decrease / decrease_count : 1.0;
}

bool CWNDFingerprinting::has_cubic_pattern(const std::vector<double>& cwnd_sequence) {
    if (cwnd_sequence.size() < 10) return false;
    
    std::vector<double> growth_rates;
    for (size_t i = 1; i < cwnd_sequence.size(); ++i) {
        if (cwnd_sequence[i] > cwnd_sequence[i-1]) {
            growth_rates.push_back(cwnd_sequence[i] - cwnd_sequence[i-1]);
        }
    }
    
    if (growth_rates.size() < 3) return false;
    
    int increasing_growth = 0;
    for (size_t i = 1; i < growth_rates.size(); ++i) {
        if (growth_rates[i] > growth_rates[i-1]) {
            increasing_growth++;
        }
    }
    
    return static_cast<double>(increasing_growth) / growth_rates.size() > 0.6;
}

bool CWNDFingerprinting::has_bbr_pattern(const std::vector<double>& cwnd_sequence) {
    if (cwnd_sequence.size() < 10) return false;
    
    double mean = std::accumulate(cwnd_sequence.begin(), cwnd_sequence.end(), 0.0) / cwnd_sequence.size();
    double variance = 0.0;
    
    for (double val : cwnd_sequence) {
        variance += (val - mean) * (val - mean);
    }
    variance /= cwnd_sequence.size();
    
    double cv = std::sqrt(variance) / mean;
    
    return cv < 0.2;
}

AlgorithmFingerprint CWNDFingerprinting::identify_algorithm(const std::vector<double>& cwnd_sequence) {
    AlgorithmFingerprint result;
    result.algorithm = CongestionAlgorithm::UNKNOWN;
    result.confidence = 0.0;
    
    if (cwnd_sequence.size() < 5) return result;
    
    double growth_rate = calculate_growth_rate(cwnd_sequence);
    double loss_response = calculate_loss_response_ratio(cwnd_sequence);
    bool cubic_pattern = has_cubic_pattern(cwnd_sequence);
    bool bbr_pattern = has_bbr_pattern(cwnd_sequence);
    
    result.signature_features = {growth_rate, loss_response, 
                                 cubic_pattern ? 1.0 : 0.0, 
                                 bbr_pattern ? 1.0 : 0.0};
    
    if (bbr_pattern) {
        result.algorithm = CongestionAlgorithm::BBR;
        result.confidence = 0.85;
    } else if (cubic_pattern) {
        result.algorithm = CongestionAlgorithm::CUBIC;
        result.confidence = 0.80;
    } else if (loss_response >= 0.45 && loss_response <= 0.55) {
        result.algorithm = CongestionAlgorithm::RENO;
        result.confidence = 0.75;
    } else if (growth_rate > 0.5) {
        result.algorithm = CongestionAlgorithm::VEGAS;
        result.confidence = 0.70;
    }
    
    return result;
}

double CWNDFingerprinting::estimate_expected_cwnd(CongestionAlgorithm algo, int rtt_ms, 
                                                   int mss, double time_since_loss, 
                                                   int packets_acked) {
    switch (algo) {
        case CongestionAlgorithm::RENO:
            return static_cast<double>(mss * packets_acked);
        
        case CongestionAlgorithm::CUBIC: {
            const double C = 0.4;
            const double beta = 0.7;
            double W_max = 100.0 * mss;
            double K = std::cbrt(W_max * (1 - beta) / C);
            return C * std::pow(time_since_loss - K, 3) + W_max;
        }
        
        case CongestionAlgorithm::BBR:
            return static_cast<double>(mss * 2.89 * rtt_ms / 1000.0);
        
        case CongestionAlgorithm::VEGAS:
            return static_cast<double>(mss * (packets_acked + 2));
        
        default:
            return static_cast<double>(mss * packets_acked);
    }
}

bool CWNDFingerprinting::detect_algorithm_switching(const std::vector<AlgorithmFingerprint>& history) {
    if (history.size() < 3) return false;
    
    int switches = 0;
    for (size_t i = 1; i < history.size(); ++i) {
        if (history[i].algorithm != history[i-1].algorithm && 
            history[i].confidence > 0.7 && history[i-1].confidence > 0.7) {
            switches++;
        }
    }
    
    return switches >= 2;
}

} // namespace covert
