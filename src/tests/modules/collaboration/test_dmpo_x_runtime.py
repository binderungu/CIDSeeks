from __future__ import annotations

import random
import pytest
import simpy
from unittest.mock import MagicMock

from simulation.core.message import Alarm
from simulation.modules.collaboration.module import CollaborationModule
from simulation.modules.privacy.module import PrivacyModule


def _alarm() -> dict:
    return {
        "message_id": "alarm-1",
        "timestamp": 0.0,
        "analyzer_node_id": 1,
        "classification_text": "suspicious_activity",
        "assessment": {"confidence": 0.9},
        "original_destination_ip": "10.0.0.1",
        "original_destination_port": 443,
        "original_message_body": "alert_body_primary",
    }


class _ReceiverCollab:
    def __init__(self) -> None:
        self.received: list[dict] = []

    def receive_alarm(self, alarm: dict, sender, wire_message=None) -> None:
        enriched_alarm = dict(alarm)
        if wire_message is not None:
            enriched_alarm["_wire_message_id"] = getattr(wire_message, "id", None)
            enriched_alarm["_wire_message_type"] = getattr(wire_message, "type", None)
        self.received.append(enriched_alarm)

    def receive_alarm_process(self, alarm: dict, sender, wire_message=None):
        self.receive_alarm(alarm, sender, wire_message=wire_message)
        if False:
            yield None


class _PeerNode:
    def __init__(self, node_id: int) -> None:
        self.id = node_id
        self.protocol_inbox: list[Alarm] = []
        self.collaboration_module = _ReceiverCollab()

    def receive_alarm_message(self, message, sender) -> dict:
        self.protocol_inbox.append(message)
        return dict(getattr(message, "data", {}) or {})


class _SenderNode:
    def __init__(self, env: simpy.Environment, sender_trust_gate_delay_ms: float = 0.0) -> None:
        self.id = 1
        self.env = env
        self.rng = random.Random(7)
        self.current_iteration = 2
        self.current_request_alarm_set_id = None
        self.protocol_outbox: list[Alarm] = []
        self.db = MagicMock()
        self.neighbors = [_PeerNode(2), _PeerNode(3), _PeerNode(4)]
        self.trust_config = {"trust_threshold": 0.0}
        self.attack_config = {"pmfa_detect_prob": 0.9, "pmfa_dmpo_resistance": 0.2}
        self.trust_alarm_contexts: list[str | None] = []
        self.trust_alarm_times: list[float] = []
        self.feature_config = {
            "privacy_strategy": "dmpo_x",
            "privacy": {
                "strategy": "dmpo_x",
                "controller": {
                    "enabled": True,
                    "budget_bw": 5.0,
                    "budget_lat_ms": 500.0,
                    "candidate_policies": [
                        {"policy_id": "tight", "K_t": 4, "f_t": 2, "ell_t": "medium", "d_t": "uniform", "r_t": 0.0},
                    ],
                },
            },
            "total_nodes": 8,
            "gossip_fanout": 3,
            "gossip_max_hops": 3,
            "min_alarm_send_delay": 0.0,
            "max_alarm_send_delay": 0.0,
            "sender_trust_gate_delay_ms": sender_trust_gate_delay_ms,
            "dmpo_pmfa_guard": True,
        }
        self.privacy_module = PrivacyModule(self)
        self.collaboration_module = CollaborationModule(self, feature_config=self.feature_config)

    def evaluate_trust(self, neighbor) -> float:
        self.trust_alarm_contexts.append(self.current_request_alarm_set_id)
        self.trust_alarm_times.append(self.env.now)
        return 0.9

    def authenticate(self, target_node) -> bool:
        return True

    def send_alarm_message(self, target_node, payload: dict):
        message = Alarm(
            source_node=str(self.id),
            target_node=str(target_node.id),
            data=dict(payload),
            message_id=str(payload.get("message_id")),
            iteration=self.current_iteration,
            correlation_id=str(payload.get("original_alarm_hash") or payload.get("message_id")),
        )
        self.protocol_outbox.append(message)
        target_node.receive_alarm_message(message, sender=self)
        return message


def test_dmpox_runtime_uses_independent_fanout_and_hidden_family_rendering() -> None:
    env = simpy.Environment()
    sender = _SenderNode(env)

    sender.collaboration_module.spread_alarm(_alarm())
    env.run()

    received = [
        alarm
        for neighbor in sender.neighbors
        for alarm in neighbor.collaboration_module.received
    ]

    assert len(received) == 2  # f_t = 2 even though K_t = 4
    assert all(not alarm.get("is_cover", False) for alarm in received)
    assert all(alarm["privacy_policy"]["K_t"] == 4 for alarm in received)
    assert all(alarm["privacy_policy"]["f_t"] == 2 for alarm in received)
    assert len({alarm["message_id"] for alarm in received}) == 2
    assert all(alarm["_wire_message_id"] == alarm["message_id"] for alarm in received)
    assert all(alarm["_wire_message_type"] == "alarm" for alarm in received)
    assert all(isinstance(alarm["stealth_header"], str) and alarm["stealth_header"].startswith("sh1:") for alarm in received)
    assert all("[f" not in str(alarm.get("current_msg", "")) for alarm in received)


def test_dmpox_sender_trust_gate_uses_alarm_family_context() -> None:
    env = simpy.Environment()
    sender = _SenderNode(env)
    alarm = _alarm()
    expected_context = sender.privacy_module._calculate_alarm_hash(alarm)

    sender.collaboration_module.spread_alarm(alarm)
    env.run()

    assert sender.current_request_alarm_set_id is None
    assert sender.trust_alarm_contexts == [expected_context, expected_context, expected_context]


def test_dmpox_sender_gate_process_consumes_simpy_time_and_records_events() -> None:
    env = simpy.Environment()
    sender = _SenderNode(env, sender_trust_gate_delay_ms=10.0)

    sender.collaboration_module.spread_alarm(_alarm())
    env.run()

    assert sender.trust_alarm_times == pytest.approx([0.01, 0.02, 0.03])
    gate_events = [
        call.kwargs
        for call in sender.db.store_event.call_args_list
        if call.kwargs.get("event_type") == "alarm_sender_gate"
    ]
    assert len(gate_events) == 3
    assert all(event["details"]["sender_gate_delay_ms"] == 10.0 for event in gate_events)
    assert all(event["details"]["sender_gate_admitted"] is True for event in gate_events)


def test_dmpox_primary_payloads_do_not_inherit_cover_flag_from_input_alarm() -> None:
    env = simpy.Environment()
    sender = _SenderNode(env)
    cover_alarm = _alarm()
    cover_alarm["is_cover"] = True

    sender.collaboration_module.spread_alarm(cover_alarm)
    env.run()

    received = [
        alarm
        for neighbor in sender.neighbors
        for alarm in neighbor.collaboration_module.received
    ]

    assert received
    assert all(alarm.get("is_cover") is False for alarm in received)
