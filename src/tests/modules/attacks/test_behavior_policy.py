import random
from types import SimpleNamespace

from simulation.modules.attacks.behavior_policy import BehaviorPolicy


def _make_node(
    *,
    node_id: int = 7,
    attack_type: str = "pmfa",
    is_malicious: bool = True,
    require_auth: bool = True,
):
    return SimpleNamespace(
        id=node_id,
        attack_type=attack_type,
        is_malicious=is_malicious,
        require_auth=require_auth,
        attack_start_tick=None,
    )


def _make_observation(
    *,
    round_id: int,
    msg_kind: str = "REQUEST",
    alarm_set_id: str = "alarm-1",
    src_id: int = 1,
    flags=None,
):
    return SimpleNamespace(
        round_id=round_id,
        msg_kind=msg_kind,
        alarm_set_id=alarm_set_id,
        src_id=src_id,
        flags=flags or {},
        is_challenge=msg_kind.upper().startswith("CHALLENGE"),
        challenge_tier=None,
        challenge_payload=None,
    )


def test_betrayal_on_off_honors_start_round():
    node = _make_node(attack_type="betrayal")
    policy = BehaviorPolicy(
        node=node,
        attack_config={
            "type": "betrayal",
            "betrayal_mode": "on_off",
            "betrayal_start_round": 5,
            "on_off_period": 4,
            "on_off_duty_cycle": 0.5,
            "honest_rating_std": 0.0,
        },
        rng=random.Random(10),
    )

    assert policy._betrayal_honest_phase(0) is True
    assert policy._betrayal_honest_phase(4) is True
    # Local round starts at betrayal_start_round (warmup complete).
    assert policy._betrayal_honest_phase(5) is True
    assert policy._betrayal_honest_phase(7) is False


def test_pmfa_fallback_assume_challenge_prefers_honest_response():
    node = _make_node(attack_type="pmfa")
    policy = BehaviorPolicy(
        node=node,
        attack_config={
            "type": "pmfa",
            "pmfa_detect_prob": 0.0,
            "pmfa_fallback_mode": "assume_challenge",
            "honest_rating_std": 0.0,
            "honest_rating_mean": 0.8,
        },
        rng=random.Random(3),
    )
    observation = _make_observation(round_id=2, msg_kind="REQUEST")
    response, flags = policy._respond_pmfa(observation, source_is_malicious=False)
    assert flags["pmfa_predicted_kind"] == "CHALLENGE"
    assert flags["pmfa_response"] == "honest"
    assert abs(response - 0.8) < 1e-9


def test_pmfa_detect_probability_reduced_by_dmpo_surface():
    node = _make_node(attack_type="pmfa")
    policy = BehaviorPolicy(
        node=node,
        attack_config={
            "type": "pmfa",
            "pmfa_detect_prob": 0.9,
            "pmfa_dmpo_resistance": 0.6,
        },
        rng=random.Random(9),
    )

    plain_obs = _make_observation(round_id=1, flags={"dmpo_enabled": False})
    guarded_obs = _make_observation(
        round_id=1,
        flags={
            "dmpo_enabled": True,
            "dmpo_variants": 4,
            "dmpo_delay_window_ms": 800.0,
            "pmfa_surface_id": "surface-a",
        },
    )
    plain_prob, plain_penalty = policy._pmfa_effective_detect_prob(plain_obs)
    guarded_prob, guarded_penalty = policy._pmfa_effective_detect_prob(guarded_obs)

    assert plain_penalty == 0.0
    assert guarded_penalty > 0.0
    assert guarded_prob < plain_prob


def test_sybil_identity_pool_expands_without_auth():
    node = _make_node(attack_type="sybil", require_auth=False)
    policy = BehaviorPolicy(
        node=node,
        attack_config={
            "type": "sybil",
            "sybil_virtual_identities": 3,
            "sybil_identity_rotation": "round_robin",
        },
        rng=random.Random(1),
    )
    obs0 = _make_observation(round_id=0, src_id=42)
    _, flags0 = policy._respond_sybil(obs0, source_is_malicious=False)
    obs1 = _make_observation(round_id=1, src_id=42)
    _, flags1 = policy._respond_sybil(obs1, source_is_malicious=False)

    assert flags0["sybil_identity_pool_size"] == 3
    assert flags1["sybil_identity_pool_size"] == 3
    assert flags0["sybil_identity_id"] != flags1["sybil_identity_id"]
