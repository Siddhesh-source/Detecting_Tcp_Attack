#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace covert {

struct TCPPacket {
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t window_size;
    double timestamp;
    uint16_t payload_size;
    bool syn;
    bool ack;
    bool fin;
    bool rst;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
};

struct CWNDAnomaly {
    double timestamp;
    double expected_cwnd;
    double observed_cwnd;
    double deviation_score;
    std::string anomaly_type;
    std::string flow_id;
};

class CWNDDetector {
public:
    explicit CWNDDetector(double sensitivity = 2.5);
    
    std::vector<CWNDAnomaly> analyze_flow(const std::vector<TCPPacket>& packets);
    double estimate_cwnd_reno(int rtt_ms, int mss, int packets_acked);
    double estimate_cwnd_cubic(int rtt_ms, int mss, double time_since_loss);
    bool detect_artificial_inflation(const std::vector<double>& cwnd_history);
    bool detect_sawtooth_encoding(const std::vector<double>& cwnd_history);
    bool detect_window_oscillation(const std::vector<double>& cwnd_history);
    
private:
    double sensitivity_;
    double calculate_entropy(const std::vector<double>& values);
    double calculate_autocorrelation(const std::vector<double>& values, int lag);
    std::vector<double> extract_cwnd_sequence(const std::vector<TCPPacket>& packets);
};

} // namespace covert
