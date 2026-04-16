from __future__ import annotations

from simulation.core.message import Alarm, Challenge, Message, TrustRequest, TrustResponse


def test_message_assigns_timestamp_when_missing() -> None:
    msg = Message(
        id="m1",
        type="custom",
        source_node="node_a",
        target_node="node_b",
        data={"x": 1},
    )
    assert isinstance(msg.timestamp, float)


def test_message_preserves_explicit_timestamp() -> None:
    msg = Message(
        id="m2",
        type="custom",
        source_node="node_a",
        target_node="node_b",
        data={},
        timestamp=123.456,
    )
    assert msg.timestamp == 123.456


def test_alarm_and_challenge_build_expected_message_shape() -> None:
    alarm = Alarm("node_src", "node_dst", {"k": "v"})
    challenge = Challenge("node_src", "node_dst", {"nonce": 7})

    assert alarm.type == "alarm"
    assert alarm.id.startswith("alarm_")
    assert alarm.source_node == "node_src"
    assert alarm.target_node == "node_dst"
    assert alarm.data["k"] == "v"

    assert challenge.type == "challenge"
    assert challenge.id.startswith("challenge_")
    assert challenge.source_node == "node_src"
    assert challenge.target_node == "node_dst"
    assert challenge.data["nonce"] == 7
    assert challenge.data["msg_kind"] == "CHALLENGE"


def test_trust_request_and_response_build_protocol_artifacts() -> None:
    request = TrustRequest(
        "node_a",
        "node_b",
        alarm_set_id="req-1",
        data={"challenge_tier": None},
        iteration=4,
        correlation_id="corr-1",
    )
    response = TrustResponse(
        "node_b",
        "node_a",
        msg_kind="REQUEST",
        response_value=0.7,
        flags={"pmfa_response": "honest"},
        data={"alarm_set_id": "req-1"},
        iteration=4,
        correlation_id=request.id,
    )

    assert request.type == "trust_request"
    assert request.data["msg_kind"] == "REQUEST"
    assert request.data["alarm_set_id"] == "req-1"
    assert request.iteration == 4
    assert request.correlation_id == "corr-1"
    assert request.payload_bytes > 0

    assert response.type == "request_response"
    assert response.data["response_value"] == 0.7
    assert response.data["flags"]["pmfa_response"] == "honest"
    assert response.correlation_id == request.id
