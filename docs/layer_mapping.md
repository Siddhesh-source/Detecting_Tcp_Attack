# OSI Layer to Feature Mapping

## Why this matters

TCP covert channel detection operates strictly at layers 3 and 4.

No payload (L7) is ever inspected. This is intentional and privacy-preserving.

## Layer 3 — Network (IP)

**Features**: src_ip, dst_ip, packet_size, protocol

**What they reveal**: who is talking, how much data

## Layer 4 — Transport (TCP)

**Features**: SYN/ACK/FIN/RST flags, window_size, retransmissions, port numbers

**What they reveal**: connection behavior, handshake anomalies, flow control abuse

## Derived Statistical Features

**Features**: IAT (inter-arrival time), flow duration, burst count, fwd/bwd ratio

**What they reveal**: timing patterns, periodicity, asymmetry — hallmarks of covert channels

## What covert channels exploit

- **Timing channels**: encode data in inter-packet delays (detected via std_iat)
- **Storage channels**: encode data in TCP header fields (detected via flag counts)
- Both leave statistical fingerprints in L3/L4 metadata
