import simpy
import pytest

from simulation.core.node import Node
from simulation.modules.ids.module import IdsModule

@pytest.fixture
def env():
    return simpy.Environment()

def _make_node(env: simpy.Environment, detection_probability: float) -> Node:
    return Node(
        id=1,
        env=env,
        is_malicious=False,
        db=None,
        feature_config={"detection_event_probability": detection_probability},
    )


def test_detect_attack_returns_none_when_probability_zero(env):
    node = _make_node(env, detection_probability=0.0)
    ids_module = IdsModule(node)

    alarm = ids_module.detect_attack()

    assert alarm is None


def test_detect_attack_returns_alarm_when_probability_one(env):
    node = _make_node(env, detection_probability=1.0)
    ids_module = IdsModule(node)

    alarm = ids_module.detect_attack()

    assert alarm is not None
    assert alarm["message_id"].startswith("alarm_1_0_")
    assert alarm["analyzer_node_id"] == 1
    assert alarm["classification_text"] == "suspicious_activity"
    assert alarm["timestamp"] == 0.0
    assert 0.0 <= alarm["assessment"]["confidence"] <= 1.0
