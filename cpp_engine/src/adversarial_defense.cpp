#include "adversarial_defense.hpp"
#include <cmath>
#include <algorithm>
#include <random>
#include <numeric>

namespace covert {

AdversarialDefense::AdversarialDefense(double epsilon, int max_iterations)
    : epsilon_(epsilon), max_iterations_(max_iterations) {}

std::vector<double> AdversarialDefense::calculate_gradient(const std::vector<double>& features) {
    std::vector<double> gradient(features.size());
    
    for (size_t i = 0; i < features.size(); ++i) {
        double h = 1e-5;
        gradient[i] = (features[i] + h - features[i]) / h;
    }
    
    double norm = 0.0;
    for (double g : gradient) {
        norm += g * g;
    }
    norm = std::sqrt(norm);
    
    if (norm > 0) {
        for (double& g : gradient) {
            g /= norm;
        }
    }
    
    return gradient;
}

std::vector<double> AdversarialDefense::fgsm_attack(const std::vector<double>& features) {
    auto gradient = calculate_gradient(features);
    
    std::vector<double> perturbed = features;
    for (size_t i = 0; i < features.size(); ++i) {
        perturbed[i] += epsilon_ * gradient[i];
        perturbed[i] = std::max(0.0, std::min(1.0, perturbed[i]));
    }
    
    return perturbed;
}

std::vector<AdversarialSample> AdversarialDefense::generate_adversarial_samples(
    const std::vector<std::vector<double>>& benign_samples,
    int num_samples) {
    
    std::vector<AdversarialSample> adversarial_samples;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, benign_samples.size() - 1);
    
    for (int i = 0; i < num_samples; ++i) {
        int idx = dis(gen);
        const auto& original = benign_samples[idx];
        
        auto perturbed = fgsm_attack(original);
        
        double magnitude = 0.0;
        for (size_t j = 0; j < original.size(); ++j) {
            magnitude += std::pow(perturbed[j] - original[j], 2);
        }
        magnitude = std::sqrt(magnitude);
        
        AdversarialSample sample;
        sample.original_features = original;
        sample.perturbed_features = perturbed;
        sample.perturbation_magnitude = magnitude;
        sample.evaded_detection = false;
        
        adversarial_samples.push_back(sample);
    }
    
    return adversarial_samples;
}

double AdversarialDefense::calculate_feature_variance(const std::vector<double>& features) {
    if (features.empty()) return 0.0;
    
    double mean = std::accumulate(features.begin(), features.end(), 0.0) / features.size();
    
    double variance = 0.0;
    for (double f : features) {
        variance += (f - mean) * (f - mean);
    }
    
    return variance / features.size();
}

bool AdversarialDefense::is_adversarial_attack(const std::vector<double>& features) {
    double variance = calculate_feature_variance(features);
    
    if (variance < 1e-6) return true;
    
    int suspicious_features = 0;
    for (double f : features) {
        if (f < 0.0 || f > 1.0) {
            suspicious_features++;
        }
    }
    
    return suspicious_features > static_cast<int>(features.size() * 0.3);
}

std::vector<double> AdversarialDefense::apply_input_sanitization(const std::vector<double>& features) {
    std::vector<double> sanitized = features;
    
    for (double& f : sanitized) {
        f = std::max(0.0, std::min(1.0, f));
    }
    
    double mean = std::accumulate(sanitized.begin(), sanitized.end(), 0.0) / sanitized.size();
    double std_dev = std::sqrt(calculate_feature_variance(sanitized));
    
    for (double& f : sanitized) {
        if (std::abs(f - mean) > 3.0 * std_dev) {
            f = mean;
        }
    }
    
    return sanitized;
}

double AdversarialDefense::calculate_robustness_score(const std::vector<double>& features) {
    auto sanitized = apply_input_sanitization(features);
    
    double distance = 0.0;
    for (size_t i = 0; i < features.size(); ++i) {
        distance += std::pow(features[i] - sanitized[i], 2);
    }
    distance = std::sqrt(distance);
    
    return 1.0 / (1.0 + distance);
}

} // namespace covert
