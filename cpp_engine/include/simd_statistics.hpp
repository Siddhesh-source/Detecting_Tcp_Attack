#pragma once
#include <vector>
#include <immintrin.h>

namespace covert {

class SIMDStatistics {
public:
    static double calculate_entropy_simd(const std::vector<uint8_t>& data);
    static double calculate_mean_simd(const std::vector<double>& data);
    static double calculate_variance_simd(const std::vector<double>& data, double mean);
    static double calculate_autocorrelation_simd(const std::vector<double>& data, int lag);
    
private:
    static constexpr size_t SIMD_WIDTH = 4;
};

} // namespace covert
