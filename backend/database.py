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

import aiosqlite

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flows.db")

CREATE_TABLE_SQL = """
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
    """Create the flows table if it does not exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(CREATE_TABLE_SQL)
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
