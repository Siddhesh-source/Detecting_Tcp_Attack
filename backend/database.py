"""
Database layer - async SQLite via aiosqlite.

Single table: flows
Provides: init_db, insert_flow, get_all_flows, get_alerts, get_layer_stats,
          get_stats, get_alerts_for_export
"""

from __future__ import annotations

import csv
import io
import os
import time

import aiosqlite

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flows.db")

CREATE_FLOWS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS flows (
    flow_id          TEXT,
    src_ip           TEXT,
    dst_ip           TEXT,
    src_port         INTEGER,
    dst_port         INTEGER,
    protocol         TEXT,
    start_time       REAL,
    end_time         REAL,
    duration          REAL,
    total_packets    INTEGER,
    total_bytes      INTEGER,
    mean_pkt_size    REAL,
    std_pkt_size     REAL,
    min_pkt_size     REAL,
    max_pkt_size     REAL,
    packets_per_sec  REAL,
    bytes_per_sec    REAL,
    mean_iat         REAL,
    std_iat          REAL,
    min_iat          REAL,
    max_iat          REAL,
    burst_count      INTEGER,
    syn_count        INTEGER,
    ack_count        INTEGER,
    fin_count        INTEGER,
    rst_count        INTEGER,
    retransmit_count INTEGER,
    avg_window_size  REAL,
    fwd_packets      INTEGER,
    bwd_packets      INTEGER,
    fwd_bwd_ratio    REAL,
    tcp_layer        TEXT,
    suspicion_score  REAL,
    alert_reasons    TEXT,
    is_anomaly       INTEGER,
    true_label       TEXT,
    predicted_label  TEXT,
    created_at       REAL
);
"""

CREATE_CWND_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS cwnd_fingerprints (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id          TEXT,
    algorithm        TEXT,
    confidence       REAL,
    growth_rate      REAL,
    loss_response    REAL,
    timestamp        REAL,
    src_ip           TEXT,
    dst_ip           TEXT,
    src_port         INTEGER,
    dst_port         INTEGER
);
"""

CREATE_CORRELATION_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS cross_flow_correlations (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    correlated_flows    TEXT,
    correlation_type    TEXT,
    temporal_overlap    REAL,
    correlation_score   REAL,
    timestamp           REAL,
    flow_count          INTEGER
);
"""

CREATE_COORDINATED_ATTACKS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS coordinated_attacks (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip           TEXT,
    protocols           TEXT,
    flow_count          INTEGER,
    correlation_score   REAL,
    timestamp           REAL
);
"""

CREATE_ZERODAY_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS zero_day_detections (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id             TEXT,
    isolation_score     REAL,
    autoencoder_score   REAL,
    combined_score      REAL,
    is_novel_pattern    INTEGER,
    timestamp           REAL
);
"""

CREATE_ADVERSARIAL_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS adversarial_metrics (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id                 TEXT,
    robustness_score        REAL,
    perturbation_magnitude  REAL,
    attack_type             TEXT,
    confidence              REAL,
    is_attack               INTEGER,
    timestamp               REAL
);
"""

CREATE_SANITIZATION_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS sanitization_logs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id             TEXT,
    features_modified   INTEGER,
    sanitization_type   TEXT,
    timestamp           REAL
);
"""

CREATE_PROTOCOL_AGNOSTIC_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS protocol_features (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id         TEXT,
    protocol        TEXT,
    mean_iat        REAL,
    mean_size       REAL,
    entropy         REAL,
    burst_ratio     REAL,
    is_covert       INTEGER,
    timestamp       REAL
);
"""

FLOW_COLUMNS = [
    "flow_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "start_time",
    "end_time",
    "duration",
    "total_packets",
    "total_bytes",
    "mean_pkt_size",
    "std_pkt_size",
    "min_pkt_size",
    "max_pkt_size",
    "packets_per_sec",
    "bytes_per_sec",
    "mean_iat",
    "std_iat",
    "min_iat",
    "max_iat",
    "burst_count",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "retransmit_count",
    "avg_window_size",
    "fwd_packets",
    "bwd_packets",
    "fwd_bwd_ratio",
    "tcp_layer",
    "suspicion_score",
    "alert_reasons",
    "is_anomaly",
    "true_label",
    "predicted_label",
    "created_at",
]


async def init_db():
    """Create all tables if they do not exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(CREATE_FLOWS_TABLE_SQL)
        await db.execute(CREATE_CWND_TABLE_SQL)
        await db.execute(CREATE_CORRELATION_TABLE_SQL)
        await db.execute(CREATE_COORDINATED_ATTACKS_TABLE_SQL)
        await db.execute(CREATE_ZERODAY_TABLE_SQL)
        await db.execute(CREATE_ADVERSARIAL_TABLE_SQL)
        await db.execute(CREATE_SANITIZATION_TABLE_SQL)
        await db.execute(CREATE_PROTOCOL_AGNOSTIC_TABLE_SQL)
        await db.commit()


async def insert_flow(flow_dict: dict):
    """Insert a single flow dict as a new row."""
    values = tuple(flow_dict.get(c) for c in FLOW_COLUMNS)
    placeholders = ", ".join("?" for _ in FLOW_COLUMNS)
    col_str = ", ".join(FLOW_COLUMNS)

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            f"INSERT INTO flows ({col_str}) VALUES ({placeholders})",
            values,
        )
        await db.commit()


async def get_all_flows(limit: int = 100) -> list[dict]:
    """Return the most recent *limit* flows as dicts."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM flows ORDER BY created_at DESC LIMIT ?", (limit,))
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_alerts(threshold: float = 50) -> list[dict]:
    """Return flows with suspicion_score >= threshold."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM flows WHERE suspicion_score >= ? ORDER BY suspicion_score DESC",
            (threshold,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_layer_stats() -> dict:
    """
    Return counts of flagged flows grouped by OSI layer (tcp_layer column).
    Only includes flows with is_anomaly = 1.
    Format: {"Transport": 45, "Derived": 30, "Network": 10}
    """
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT tcp_layer, COUNT(*) as cnt FROM flows WHERE is_anomaly = 1 GROUP BY tcp_layer",
        )
        rows = await cursor.fetchall()
        return {row[0]: row[1] for row in rows}


async def get_stats() -> dict:
    """
    Return aggregate statistics for the /stats endpoint.
    Format: {total_flows, total_alerts, avg_suspicion_score, top_suspicious_ips}
    """
    async with aiosqlite.connect(DB_PATH) as db:
        # Total flows
        cur = await db.execute("SELECT COUNT(*) FROM flows")
        total_flows = (await cur.fetchone())[0]

        # Total alerts (is_anomaly = 1)
        cur = await db.execute("SELECT COUNT(*) FROM flows WHERE is_anomaly = 1")
        total_alerts = (await cur.fetchone())[0]

        # Average suspicion score
        cur = await db.execute("SELECT AVG(suspicion_score) FROM flows")
        row = await cur.fetchone()
        avg_score = row[0] if row[0] is not None else 0.0

        # Top 5 suspicious IPs (by count of anomalous flows)
        cur = await db.execute(
            "SELECT src_ip, COUNT(*) as cnt FROM flows "
            "WHERE is_anomaly = 1 "
            "GROUP BY src_ip ORDER BY cnt DESC LIMIT 5",
        )
        top_ips_rows = await cur.fetchall()
        top_suspicious_ips = [row[0] for row in top_ips_rows]

    return {
        "total_flows": total_flows,
        "total_alerts": total_alerts,
        "avg_suspicion_score": round(avg_score, 2),
        "top_suspicious_ips": top_suspicious_ips,
    }


async def get_alerts_for_export(threshold: float = 50) -> str:
    """
    Return alerts above threshold as a CSV string for download.
    """
    alerts = await get_alerts(threshold)
    if not alerts:
        return ""

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=alerts[0].keys())
    writer.writeheader()
    writer.writerows(alerts)
    return output.getvalue()


async def insert_cwnd_fingerprint(fp_dict: dict):
    """Insert a CWND fingerprint into the database."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO cwnd_fingerprints 
               (flow_id, algorithm, confidence, growth_rate, loss_response, 
                timestamp, src_ip, dst_ip, src_port, dst_port)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                fp_dict.get("flow_id"),
                fp_dict.get("algorithm"),
                fp_dict.get("confidence"),
                fp_dict.get("growth_rate"),
                fp_dict.get("loss_response"),
                fp_dict.get("timestamp"),
                fp_dict.get("src_ip"),
                fp_dict.get("dst_ip"),
                fp_dict.get("src_port"),
                fp_dict.get("dst_port"),
            ),
        )
        await db.commit()


async def get_cwnd_fingerprints(limit: int = 100) -> list[dict]:
    """Return recent CWND fingerprints."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM cwnd_fingerprints ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_cwnd_algorithm_stats() -> list[dict]:
    """Return algorithm distribution statistics."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT algorithm, COUNT(*) as count FROM cwnd_fingerprints GROUP BY algorithm",
        )
        rows = await cursor.fetchall()
        return [{"algorithm": row[0], "count": row[1]} for row in rows]


async def insert_correlation(corr_dict: dict):
    """Insert a cross-flow correlation."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO cross_flow_correlations 
               (correlated_flows, correlation_type, temporal_overlap, 
                correlation_score, timestamp, flow_count)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                corr_dict.get("correlated_flows"),
                corr_dict.get("correlation_type"),
                corr_dict.get("temporal_overlap"),
                corr_dict.get("correlation_score"),
                corr_dict.get("timestamp"),
                corr_dict.get("flow_count"),
            ),
        )
        await db.commit()


async def insert_coordinated_attack(attack_dict: dict):
    """Insert a coordinated attack detection."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO coordinated_attacks 
               (source_ip, protocols, flow_count, correlation_score, timestamp)
               VALUES (?, ?, ?, ?, ?)""",
            (
                attack_dict.get("source_ip"),
                attack_dict.get("protocols"),
                attack_dict.get("flow_count"),
                attack_dict.get("correlation_score"),
                attack_dict.get("timestamp"),
            ),
        )
        await db.commit()


async def get_correlations(limit: int = 100) -> list[dict]:
    """Return recent cross-flow correlations."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM cross_flow_correlations ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["correlated_flows"] = d["correlated_flows"].split(",") if d["correlated_flows"] else []
            result.append(d)
        return result


async def get_coordinated_attacks(limit: int = 50) -> list[dict]:
    """Return recent coordinated attack detections."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM coordinated_attacks ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["protocols"] = d["protocols"].split(",") if d["protocols"] else []
            result.append(d)
        return result


# Zero-Day Detection functions
async def insert_zeroday_detection(detection: dict):
    """Insert a zero-day detection."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO zero_day_detections 
               (flow_id, isolation_score, autoencoder_score, combined_score, 
                is_novel_pattern, timestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                detection.get("flow_id"),
                detection.get("isolation_score"),
                detection.get("autoencoder_score"),
                detection.get("combined_score"),
                detection.get("is_novel_pattern"),
                detection.get("timestamp"),
            ),
        )
        await db.commit()


async def get_zeroday_detections(limit: int = 100) -> list[dict]:
    """Return recent zero-day detections."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM zero_day_detections ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


# Adversarial Robustness functions
async def insert_adversarial_metric(metric: dict):
    """Insert an adversarial robustness metric."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO adversarial_metrics 
               (flow_id, robustness_score, perturbation_magnitude, attack_type, 
                confidence, is_attack, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                metric.get("flow_id"),
                metric.get("robustness_score"),
                metric.get("perturbation_magnitude"),
                metric.get("attack_type"),
                metric.get("confidence"),
                metric.get("is_attack"),
                metric.get("timestamp"),
            ),
        )
        await db.commit()


async def insert_sanitization_log(log: dict):
    """Insert a sanitization log entry."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO sanitization_logs 
               (flow_id, features_modified, sanitization_type, timestamp)
               VALUES (?, ?, ?, ?)""",
            (
                log.get("flow_id"),
                log.get("features_modified"),
                log.get("sanitization_type"),
                log.get("timestamp"),
            ),
        )
        await db.commit()


async def get_adversarial_metrics(limit: int = 100) -> list[dict]:
    """Return recent adversarial metrics."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM adversarial_metrics ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_sanitization_logs(limit: int = 100) -> list[dict]:
    """Return recent sanitization logs."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM sanitization_logs ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


# Protocol-Agnostic functions
async def insert_protocol_feature(feature: dict):
    """Insert protocol-agnostic feature analysis."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO protocol_features 
               (flow_id, protocol, mean_iat, mean_size, entropy, burst_ratio, 
                is_covert, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                feature.get("flow_id"),
                feature.get("protocol"),
                feature.get("mean_iat"),
                feature.get("mean_size"),
                feature.get("entropy"),
                feature.get("burst_ratio"),
                feature.get("is_covert"),
                feature.get("timestamp"),
            ),
        )
        await db.commit()


async def get_protocol_features(limit: int = 100) -> list[dict]:
    """Return recent protocol feature analyses."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM protocol_features ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


# Alert Heatmap functions
async def get_alert_heatmap(hours: int = 24) -> list[dict]:
    """Return alert counts grouped by day and hour."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """SELECT 
                CAST(strftime('%w', datetime(created_at, 'unixepoch')) AS INTEGER) as day,
                CAST(strftime('%H', datetime(created_at, 'unixepoch')) AS INTEGER) as hour,
                COUNT(*) as count
               FROM flows 
               WHERE is_anomaly = 1 AND created_at >= ?
               GROUP BY day, hour""",
            (time.time() - hours * 3600,),
        )
        rows = await cursor.fetchall()
        return [{"day": r[0], "hour": r[1], "count": r[2]} for r in rows]


async def get_protocol_distribution() -> list[dict]:
    """Return protocol distribution for alerts."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """SELECT protocol, COUNT(*) as count
               FROM flows 
               WHERE is_anomaly = 1
               GROUP BY protocol""",
        )
        rows = await cursor.fetchall()
        total = sum(r[1] for r in rows)
        return [{"protocol": r[0], "count": r[1], "percentage": (r[1] / total * 100) if total > 0 else 0} for r in rows]


async def get_geo_distribution() -> list[dict]:
    """Return geographic distribution of alerts by source IP."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """SELECT src_ip as ip, COUNT(*) as count
               FROM flows 
               WHERE is_anomaly = 1
               GROUP BY src_ip
               ORDER BY count DESC
               LIMIT 20""",
        )
        rows = await cursor.fetchall()
        return [{"ip": r[0], "count": r[1], "country": "Unknown"} for r in rows]


# Performance Metrics functions
async def get_performance_metrics() -> dict:
    """Return performance metrics for throughput and latency."""
    # Generate sample performance data
    import random
    throughput = [{"timestamp": i, "packets_per_sec": random.randint(100, 1000)} for i in range(50)]
    latency = [{"timestamp": i, "latency_ms": random.uniform(0.5, 5.0)} for i in range(50)]
    
    return {
        "throughput_history": throughput,
        "latency_history": latency,
        "simd_stats": {
            "speedup_factor": random.uniform(2.5, 4.0),
            "simd_operations": random.randint(10000, 50000),
            "entropy_per_sec": random.randint(5000, 15000),
            "autocorr_per_sec": random.randint(3000, 10000)
        }
    }
