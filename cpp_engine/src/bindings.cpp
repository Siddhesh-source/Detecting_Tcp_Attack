#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "cwnd_detector.hpp"
#include "qos_detector.hpp"
#include "cwnd_fingerprinting.hpp"
#include "cross_flow_correlation.hpp"
#include "zero_day_detector.hpp"
#include "simd_statistics.hpp"
#include "adversarial_defense.hpp"
#include "protocol_agnostic.hpp"

namespace py = pybind11;

PYBIND11_MODULE(covert_engine, m) {
    m.doc() = "High-performance C++ covert channel detection engine with novel detection methods";

    // Enums
    py::enum_<covert::CongestionAlgorithm>(m, "CongestionAlgorithm")
        .value("UNKNOWN", covert::CongestionAlgorithm::UNKNOWN)
        .value("RENO", covert::CongestionAlgorithm::RENO)
        .value("CUBIC", covert::CongestionAlgorithm::CUBIC)
        .value("BBR", covert::CongestionAlgorithm::BBR)
        .value("VEGAS", covert::CongestionAlgorithm::VEGAS);

    // TCPPacket struct
    py::class_<covert::TCPPacket>(m, "TCPPacket")
        .def(py::init<>())
        .def_readwrite("seq_num", &covert::TCPPacket::seq_num)
        .def_readwrite("ack_num", &covert::TCPPacket::ack_num)
        .def_readwrite("window_size", &covert::TCPPacket::window_size)
        .def_readwrite("timestamp", &covert::TCPPacket::timestamp)
        .def_readwrite("payload_size", &covert::TCPPacket::payload_size)
        .def_readwrite("syn", &covert::TCPPacket::syn)
        .def_readwrite("ack", &covert::TCPPacket::ack)
        .def_readwrite("fin", &covert::TCPPacket::fin)
        .def_readwrite("rst", &covert::TCPPacket::rst)
        .def_readwrite("src_ip", &covert::TCPPacket::src_ip)
        .def_readwrite("dst_ip", &covert::TCPPacket::dst_ip)
        .def_readwrite("src_port", &covert::TCPPacket::src_port)
        .def_readwrite("dst_port", &covert::TCPPacket::dst_port);

    // CWNDAnomaly struct
    py::class_<covert::CWNDAnomaly>(m, "CWNDAnomaly")
        .def(py::init<>())
        .def_readwrite("timestamp", &covert::CWNDAnomaly::timestamp)
        .def_readwrite("expected_cwnd", &covert::CWNDAnomaly::expected_cwnd)
        .def_readwrite("observed_cwnd", &covert::CWNDAnomaly::observed_cwnd)
        .def_readwrite("deviation_score", &covert::CWNDAnomaly::deviation_score)
        .def_readwrite("anomaly_type", &covert::CWNDAnomaly::anomaly_type)
        .def_readwrite("flow_id", &covert::CWNDAnomaly::flow_id);

    // CWNDDetector class
    py::class_<covert::CWNDDetector>(m, "CWNDDetector")
        .def(py::init<double>(), py::arg("sensitivity") = 2.5)
        .def("analyze_flow", &covert::CWNDDetector::analyze_flow)
        .def("estimate_cwnd_reno", &covert::CWNDDetector::estimate_cwnd_reno)
        .def("estimate_cwnd_cubic", &covert::CWNDDetector::estimate_cwnd_cubic)
        .def("detect_artificial_inflation", &covert::CWNDDetector::detect_artificial_inflation)
        .def("detect_sawtooth_encoding", &covert::CWNDDetector::detect_sawtooth_encoding)
        .def("detect_window_oscillation", &covert::CWNDDetector::detect_window_oscillation);

    // IPPacket struct
    py::class_<covert::IPPacket>(m, "IPPacket")
        .def(py::init<>())
        .def_readwrite("dscp", &covert::IPPacket::dscp)
        .def_readwrite("ecn", &covert::IPPacket::ecn)
        .def_readwrite("total_length", &covert::IPPacket::total_length)
        .def_readwrite("timestamp", &covert::IPPacket::timestamp)
        .def_readwrite("src_ip", &covert::IPPacket::src_ip)
        .def_readwrite("dst_ip", &covert::IPPacket::dst_ip)
        .def_readwrite("ip_id", &covert::IPPacket::ip_id);

    // QoSAnomaly struct
    py::class_<covert::QoSAnomaly>(m, "QoSAnomaly")
        .def(py::init<>())
        .def_readwrite("timestamp", &covert::QoSAnomaly::timestamp)
        .def_readwrite("dscp_value", &covert::QoSAnomaly::dscp_value)
        .def_readwrite("frequency", &covert::QoSAnomaly::frequency)
        .def_readwrite("expected_frequency", &covert::QoSAnomaly::expected_frequency)
        .def_readwrite("anomaly_type", &covert::QoSAnomaly::anomaly_type)
        .def_readwrite("score", &covert::QoSAnomaly::score)
        .def_readwrite("flow_id", &covert::QoSAnomaly::flow_id);

    // QoSDetector class
    py::class_<covert::QoSDetector>(m, "QoSDetector")
        .def(py::init<double>(), py::arg("threshold") = 0.7)
        .def("analyze_dscp_patterns", &covert::QoSDetector::analyze_dscp_patterns)
        .def("detect_dscp_hopping", &covert::QoSDetector::detect_dscp_hopping)
        .def("detect_priority_encoding", &covert::QoSDetector::detect_priority_encoding)
        .def("detect_ecn_abuse", &covert::QoSDetector::detect_ecn_abuse)
        .def("calculate_dscp_entropy", &covert::QoSDetector::calculate_dscp_entropy)
        .def("build_dscp_profile", &covert::QoSDetector::build_dscp_profile);
}
