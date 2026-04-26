#pragma once
#include <vector>
#include <string>

namespace covert {

struct AdversarialSample {
    std::vector<double> original_features;
    std::vector<double> perturbed_features;
    double perturbation_magnitude;
    bool evaded_detection;
};

class AdversarialDefense {
public:
    AdversarialDefense(double epsilon = 0.1, int max_iterations = 10);
    
    std::vector<AdversarialSample> generate_adversarial_samples(
        const std::vector<std::vector<double>>& benign_samples,
        int num_samples);
    
    bool is_adversarial_attack(const std::vector<double>& features);
    
    std::vector<double> apply_input_sanitization(const std::vector<double>& features);
    
    double calculate_robustness_score(const std::vector<double>& features);
    
private:
    double epsilon_;
    int max_iterations_;
    
    std::vector<double> fgsm_attack(const std::vector<double>& features);
    std::vector<double> calculate_gradient(const std::vector<double>& features);
    double calculate_feature_variance(const std::vector<double>& features);
};

} // namespace covert
