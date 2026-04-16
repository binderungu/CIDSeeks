from __future__ import annotations

import json
from pathlib import Path

from simulation.modules.database.node_database import NodeDatabase


def _make_db(tmp_path: Path) -> NodeDatabase:
    return NodeDatabase(db_path=str(tmp_path / "test_simulation.db"))


def test_numeric_coercion_helpers_handle_invalid_values(tmp_path: Path) -> None:
    db = _make_db(tmp_path)

    assert db._as_int("7") == 7
    assert db._as_int(None, default=5) == 5
    assert db._as_int("bad", default=9) == 9

    assert db._as_float("1.5") == 1.5
    assert db._as_float("bad", default=2.5) == 2.5

    assert db._as_optional_int("3") == 3
    assert db._as_optional_int(None) is None
    assert db._as_optional_int("oops") is None

    assert db._as_optional_float("3.25") == 3.25
    assert db._as_optional_float(None) is None
    assert db._as_optional_float("oops") is None


def test_store_node_round_rows_and_round_metrics_persist_expected_values(tmp_path: Path) -> None:
    db = _make_db(tmp_path)

    db.store_node_round_rows(
        "exp-1",
        4,
        [
            {
                "node_id": "1",
                "label_is_malicious": "1",
                "trust": "0.75",
                "pred_is_malicious": 0,
                "was_quarantined": 1,
                "ttd_round": "3",
                "sent_msgs": "10",
                "recv_msgs": 12,
                "bytes_sent": "100",
                "bytes_recv": 120,
                "cpu_ms": "5.5",
                "mem_bytes": "2048",
            },
            {
                "node_id": "bad",
                "trust": "bad",
                "ttd_round": "bad",
                "cpu_ms": None,
                "mem_bytes": None,
            },
        ],
    )

    rows = db.execute_query(
        "SELECT node_id, trust, ttd_round, cpu_ms, mem_bytes FROM node_round WHERE exp_id = ? ORDER BY node_id",
        ("exp-1",),
    ).fetchall()
    assert len(rows) == 2
    assert rows[0]["node_id"] == 0  # invalid string coerced to default 0
    assert rows[0]["trust"] == 0.0
    assert rows[0]["ttd_round"] is None
    assert rows[1]["node_id"] == 1
    assert rows[1]["trust"] == 0.75
    assert rows[1]["ttd_round"] == 3
    assert rows[1]["cpu_ms"] == 5.5
    assert rows[1]["mem_bytes"] == 2048

    db.store_round_metrics(
        "exp-1",
        4,
        {
            "auc_node": "0.88",
            "delta_tau": "0.11",
            "cohens_d": None,
            "tpr_node": "bad",
            "fpr_honest": "0.02",
            "avg_cpu_ms_node": "4.2",
            "avg_mem_node": "8192",
            "total_msgs": "40",
            "total_bytes": "4000",
            "overhead_pct": None,
            "consensus_p50_ms": "12.0",
            "consensus_p95_ms": "20.0",
            "ledger_growth_bytes": "256",
        },
    )
    metric_row = db.execute_query(
        "SELECT auc_node, delta_tau, cohens_d, tpr_node, total_msgs, ledger_growth_bytes FROM round_metrics WHERE exp_id = ? AND round = ?",
        ("exp-1", 4),
    ).fetchone()
    assert metric_row is not None
    assert metric_row["auc_node"] == 0.88
    assert metric_row["delta_tau"] == 0.11
    assert metric_row["cohens_d"] is None
    assert metric_row["tpr_node"] is None
    assert metric_row["total_msgs"] == 40
    assert metric_row["ledger_growth_bytes"] == 256


def test_store_event_chains_hash_and_get_iteration_events_formats_details(tmp_path: Path) -> None:
    db = _make_db(tmp_path)

    db.store_event(
        timestamp=1.0,
        iteration=1,
        node_id=7,
        event_type="alpha",
        details={"description": "first"},
        related_node_id=2,
    )
    db.store_event(
        timestamp=2.0,
        iteration=2,
        node_id=7,
        event_type="beta",
        details={"description": "second"},
        related_node_id=3,
    )

    rows = db.execute_query(
        "SELECT details FROM events WHERE node_id = ? ORDER BY iteration ASC",
        (7,),
    ).fetchall()
    assert len(rows) == 2
    details_1 = json.loads(rows[0]["details"])
    details_2 = json.loads(rows[1]["details"])
    assert details_1["prev_hash"] is None
    assert isinstance(details_1["event_hash"], str) and details_1["event_hash"]
    assert details_2["prev_hash"] == details_1["event_hash"]
    assert isinstance(details_2["event_hash"], str) and details_2["event_hash"]

    events = db.get_iteration_events(7)
    assert len(events) == 2
    assert events[0]["iteration"] == 1
    assert "alpha: first" in events[0]["detail"]
    assert "(with Node 2)" in events[0]["detail"]
    assert "beta: second" in events[1]["detail"]


def test_get_iteration_events_returns_fallback_when_none_found(tmp_path: Path) -> None:
    db = _make_db(tmp_path)

    events = db.get_iteration_events(999)
    assert len(events) == 2
    assert events[0]["iteration"] == 1
    assert "Node 999" in events[0]["detail"]


def test_execute_query_result_supports_context_manager_and_legacy_connection_close(tmp_path: Path) -> None:
    db = _make_db(tmp_path)

    with db.execute_query("SELECT COUNT(*) AS count FROM nodes") as result:
        row = result.fetchone()

    assert row is not None
    assert row["count"] == 0

    # UI code still calls cursor.connection.close(); keep that path harmless.
    result.connection.close()
