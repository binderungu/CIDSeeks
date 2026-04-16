from __future__ import annotations

from collections import defaultdict
import random
from unittest.mock import MagicMock

import simpy

from simulation.core.message import Alarm
from simulation.modules.collaboration.module import CollaborationModule


def _received_alarm() -> dict:
    return {
        "message_id": "alarm-77",
        "original_alarm_hash": "family-77",
        "classification_text": "suspicious_activity",
        "assessment": {"confidence": 0.95},
        "gossip_hops": 0,
    }


class _TraceTrustManager:
    def __init__(self) -> None:
        self.traces: dict[int, dict] = {}

    def get_last_evaluation_trace(self, target_id: int) -> dict:
        return dict(self.traces.get(int(target_id), {}))


class _SenderNode:
    def __init__(self, node_id: int) -> None:
        self.id = node_id


class _ReceiverNode:
    def __init__(self, env: simpy.Environment, trust_score: float, trust_gate_delay_ms: float = 0.0) -> None:
        self.id = 2
        self.env = env
        self.rng = random.Random(11)
        self.current_iteration = 7
        self.current_request_alarm_set_id = None
        self.db = MagicMock()
        self.neighbors = []
        self.trust_config = {"trust_threshold": 0.6}
        self.feature_config = {
            "total_nodes": 4,
            "gossip_fanout": 1,
            "gossip_max_hops": 0,
            "trust_gate_delay_ms": trust_gate_delay_ms,
        }
        self.quarantined_nodes = set()
        self.alarms: list[dict] = []
        self.contribution_counts = defaultdict(int)
        self.trust_manager = _TraceTrustManager()
        self.trust_score = trust_score
        self.evaluated_contexts: list[str | None] = []
        self.collaboration_module = CollaborationModule(self, feature_config=self.feature_config)

    def evaluate_trust(self, sender) -> float:
        self.evaluated_contexts.append(self.current_request_alarm_set_id)
        self.trust_manager.traces[sender.id] = {
            "msg_kind": "REQUEST",
            "alarm_set_id": self.current_request_alarm_set_id,
            "challenge_tier": None,
            "protocol_request_id": f"request_{self.id}_{sender.id}_{self.current_iteration}",
            "protocol_request_type": "trust_request",
            "protocol_response_id": f"response_{sender.id}_{self.id}_{self.current_iteration}",
            "protocol_response_type": "request_response",
            "pmfa_surface_id": "surface-77",
            "trust_before": 0.5,
            "trust_after": self.trust_score,
        }
        return self.trust_score


def test_receive_alarm_records_trust_gate_trace_on_accept() -> None:
    env = simpy.Environment()
    receiver = _ReceiverNode(env, trust_score=0.9)
    sender = _SenderNode(9)
    wire_message = Alarm(
        source_node=str(sender.id),
        target_node=str(receiver.id),
        data=_received_alarm(),
        message_id="alarm-77",
        iteration=receiver.current_iteration,
        correlation_id="family-77",
    )

    receiver.collaboration_module.receive_alarm(_received_alarm(), sender, wire_message=wire_message)

    assert receiver.evaluated_contexts == ["family-77"]
    assert receiver.current_request_alarm_set_id is None
    assert len(receiver.alarms) == 1

    received_events = [
        call.kwargs
        for call in receiver.db.store_event.call_args_list
        if call.kwargs.get("event_type") == "alarm_received"
    ]
    assert len(received_events) == 1
    details = received_events[0]["details"]
    assert details["trust_gate_alarm_set_id"] == "family-77"
    assert details["trust_gate_msg_kind"] == "REQUEST"
    assert details["trust_gate_protocol_request_id"] == "request_2_9_7"
    assert details["trust_gate_protocol_response_id"] == "response_9_2_7"
    assert details["alarm_wire_message_id"] == "alarm-77"
    assert details["alarm_wire_message_type"] == "alarm"
    assert details["alarm_wire_correlation_id"] == "family-77"
    assert details["trust_gate_delay_ms"] == 0.0
    assert details["trust_gate_trust_after"] == 0.9


def test_receive_alarm_records_trust_gate_trace_on_low_trust_reject() -> None:
    env = simpy.Environment()
    receiver = _ReceiverNode(env, trust_score=0.2)
    sender = _SenderNode(9)
    wire_message = Alarm(
        source_node=str(sender.id),
        target_node=str(receiver.id),
        data=_received_alarm(),
        message_id="alarm-77",
        iteration=receiver.current_iteration,
        correlation_id="family-77",
    )

    receiver.collaboration_module.receive_alarm(_received_alarm(), sender, wire_message=wire_message)

    assert receiver.evaluated_contexts == ["family-77"]
    assert receiver.current_request_alarm_set_id is None
    assert receiver.alarms == []

    rejected_events = [
        call.kwargs
        for call in receiver.db.store_event.call_args_list
        if call.kwargs.get("event_type") == "alarm_ignored_low_trust"
    ]
    assert len(rejected_events) == 1
    details = rejected_events[0]["details"]
    assert details["alarm_id"] == "alarm-77"
    assert details["trust_gate_alarm_set_id"] == "family-77"
    assert details["trust_gate_protocol_request_type"] == "trust_request"
    assert details["trust_gate_protocol_response_type"] == "request_response"
    assert details["alarm_wire_message_id"] == "alarm-77"
    assert details["alarm_wire_message_type"] == "alarm"
    assert details["trust_gate_delay_ms"] == 0.0
    assert details["trust_gate_trust_after"] == 0.2


def test_receive_alarm_process_consumes_simpy_time_for_gate_delay() -> None:
    env = simpy.Environment()
    receiver = _ReceiverNode(env, trust_score=0.9, trust_gate_delay_ms=25.0)
    sender = _SenderNode(9)
    wire_message = Alarm(
        source_node=str(sender.id),
        target_node=str(receiver.id),
        data=_received_alarm(),
        message_id="alarm-77",
        iteration=receiver.current_iteration,
        correlation_id="family-77",
    )

    env.process(receiver.collaboration_module.receive_alarm_process(_received_alarm(), sender, wire_message=wire_message))
    env.run()

    assert env.now == 0.025
    received_events = [
        call.kwargs
        for call in receiver.db.store_event.call_args_list
        if call.kwargs.get("event_type") == "alarm_received"
    ]
    assert len(received_events) == 1
    details = received_events[0]["details"]
    assert details["trust_gate_delay_ms"] == 25.0
