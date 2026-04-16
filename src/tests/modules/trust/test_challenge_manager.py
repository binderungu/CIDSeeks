from __future__ import annotations

import random
from types import SimpleNamespace

from simulation.core.message import Message
from simulation.modules.trust.challenge_manager import ChallengeManager


class _DummyEnv:
    def __init__(self, now: float = 0.0) -> None:
        self.now = now


class _DummyNode:
    def __init__(self, node_id: int = 1) -> None:
        self.id = node_id
        self.env = _DummyEnv(now=12.5)
        self.current_iteration = 3
        self.rng = random.Random(123)
        self.sent_messages: list[tuple[int, dict]] = []

    def send_message(self, target_id: int, payload: dict) -> None:
        self.sent_messages.append((target_id, payload))


def test_generate_nonce_is_hex_and_deterministic_length() -> None:
    node = _DummyNode()
    manager = ChallengeManager(node)

    nonce = manager._generate_nonce(length=8)
    assert len(nonce) == 16
    assert all(ch in "0123456789abcdef" for ch in nonce)


def test_generate_challenge_basic_includes_nonce() -> None:
    node = _DummyNode()
    manager = ChallengeManager(node)
    target = _DummyNode(node_id=9)

    challenge = manager._generate_challenge(target, "basic")
    assert challenge is not None
    assert challenge["type"] == "challenge"
    assert challenge["level"] == "basic"
    assert challenge["source_node"] == node.id
    assert "nonce" in challenge


def test_maybe_initiate_challenge_sends_when_api_available(monkeypatch) -> None:
    node = _DummyNode(node_id=2)
    target = _DummyNode(node_id=7)
    manager = ChallengeManager(node)

    monkeypatch.setattr(manager, "_should_challenge", lambda *_args: True)
    monkeypatch.setattr(manager, "_determine_challenge_level", lambda *_args: "advanced")

    result = manager.maybe_initiate_challenge(target)

    assert result is None
    assert len(node.sent_messages) == 1
    target_id, payload = node.sent_messages[0]
    assert target_id == target.id
    assert payload["level"] == "advanced"


def test_maybe_initiate_challenge_does_not_fail_when_send_api_missing(monkeypatch) -> None:
    node = SimpleNamespace(id=4, env=_DummyEnv(now=4.0), current_iteration=1, rng=random.Random(9))
    target = _DummyNode(node_id=6)
    manager = ChallengeManager(node)  # type: ignore[arg-type]

    monkeypatch.setattr(manager, "_should_challenge", lambda *_args: True)
    monkeypatch.setattr(manager, "_determine_challenge_level", lambda *_args: "final")

    result = manager.maybe_initiate_challenge(target)
    assert result is None


def test_handle_challenge_response_accepts_message_shape() -> None:
    node = _DummyNode()
    manager = ChallengeManager(node)
    message = Message(
        id="resp1",
        type="challenge_response",
        source_node="9",
        target_node="1",
        data={"level": "advanced", "ok": True},
    )

    manager.handle_challenge_response(message)


def test_should_challenge_and_determine_level_use_rng() -> None:
    node = _DummyNode()
    manager = ChallengeManager(node)
    target = _DummyNode(node_id=8)

    decision = manager._should_challenge(target)
    level = manager._determine_challenge_level(target)

    assert isinstance(decision, bool)
    assert level in {"basic", "advanced", "final"}


def test_should_challenge_without_rng_returns_false() -> None:
    node = SimpleNamespace(id=1, env=_DummyEnv(now=0), current_iteration=0, rng=None)
    manager = ChallengeManager(node)  # type: ignore[arg-type]

    assert manager._should_challenge(SimpleNamespace(id=2)) is False
    assert manager._determine_challenge_level(SimpleNamespace(id=2)) == "basic"
