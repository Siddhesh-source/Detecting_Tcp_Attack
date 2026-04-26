#include "simd_statistics.hpp"
#include <cmath>
#include <unordered_map>
#include <algorithm>

namespace covert {

double SIMDStatistics::calculate_mean_simd(const std::vector<double>& data) {
    if (data.empty()) return 0.0;
    
    size_t n = data.size();
    size_t simd_end = (n / 4) * 4;
    
    __m256d sum_vec = _mm256_setzero_pd();
    
    for (size_t i = 0; i < simd_end; i += 4) {
        __m256d data_vec = _mm256_loadu_pd(&data[i]);
        sum_vec = _mm256_add_pd(sum_vec, data_vec);
    }
    
    double sum_array[4];
    _mm256_storeu_pd(sum_array, sum_vec);
    double sum = sum_array[0] + sum_array[1] + sum_array[2] + sum_array[3];
    
    for (size_t i = simd_end; i < n; ++i) {
        sum += data[i];
    }
    
    return sum / n;
}

double SIMDStatistics::calculate_variance_simd(const std::vector<double>& data, double mean) {
    if (data.empty()) return 0.0;
    
    size_t n = data.size();
    size_t simd_end = (n / 4) * 4;
    
    __m256d mean_vec = _mm256_set1_pd(mean);
    __m256d sum_sq_vec = _mm256_setzero_pd();
    
    for (size_t i = 0; i < simd_end; i += 4) {
        __m256d data_vec = _mm256_loadu_pd(&data[i]);
        __m256d diff = _mm256_sub_pd(data_vec, mean_vec);
        __m256d sq = _mm256_mul_pd(diff, diff);
        sum_sq_vec = _mm256_add_pd(sum_sq_vec, sq);
    }
    
    double sum_sq_array[4];
    _mm256_storeu_pd(sum_sq_array, sum_sq_vec);
    double sum_sq = sum_sq_array[0] + sum_sq_array[1] + sum_sq_array[2] + sum_sq_array[3];
    
    for (size_t i = simd_end; i < n; ++i) {
        double diff = data[i] - mean;
        sum_sq += diff * diff;
    }
    
    return sum_sq / n;
}

double SIMDStatistics::calculate_entropy_simd(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;
    
    std::unordered_map<uint8_t, int> freq;
    for (uint8_t val : data) {
        freq[val]++;
    }
    
    double entropy = 0.0;
    double total = static_cast<double>(data.size());
    
    for (const auto& [val, count] : freq) {
        double p = count / total;
        if (p > 0) {
            entropy -= p * std::log2(p);
        }
    }
    
    return entropy;
}

double SIMDStatistics::calculate_autocorrelation_simd(const std::vector<double>& data, int lag) {
    if (data.size() <= static_cast<size_t>(lag)) return 0.0;
    
    double mean = calculate_mean_simd(data);
    
    size_t n = data.size() - lag;
    size_t simd_end = (n / 4) * 4;
    
    __m256d mean_vec = _mm256_set1_pd(mean);
    __m256d numerator_vec = _mm256_setzero_pd();
    __m256d denominator_vec = _mm256_setzero_pd();
    
    for (size_t i = 0; i < simd_end; i += 4) {
        __m256d data1 = _mm256_loadu_pd(&data[i]);
        __m256d data2 = _mm256_loadu_pd(&data[i + lag]);
        
        __m256d diff1 = _mm256_sub_pd(data1, mean_vec);
        __m256d diff2 = _mm256_sub_pd(data2, mean_vec);
        
        __m256d prod = _mm256_mul_pd(diff1, diff2);
        numerator_vec = _mm256_add_pd(numerator_vec, prod);
        
        __m256d sq = _mm256_mul_pd(diff1, diff1);
        denominator_vec = _mm256_add_pd(denominator_vec, sq);
    }
    
    double num_array[4], den_array[4];
    _mm256_storeu_pd(num_array, numerator_vec);
    _mm256_storeu_pd(den_array, denominator_vec);
    
    double numerator = num_array[0] + num_array[1] + num_array[2] + num_array[3];
    double denominator = den_array[0] + den_array[1] + den_array[2] + den_array[3];
    
    for (size_t i = simd_end; i < n; ++i) {
        numerator += (data[i] - mean) * (data[i + lag] - mean);
        denominator += (data[i] - mean) * (data[i] - mean);
    }
    
    return denominator > 0 ? numerator / denominator : 0.0;
}

} // namespace covert
